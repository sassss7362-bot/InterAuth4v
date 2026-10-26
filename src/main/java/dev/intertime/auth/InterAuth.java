package dev.intertime.auth;

import io.papermc.paper.event.player.AsyncChatEvent;
import net.kyori.adventure.bossbar.BossBar;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.kyori.adventure.title.Title;
import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * InterAuth — авторизация /reg и /l.
 *  - таймер (боссбар) вверху экрана: регистрация / авторизация
 *  - напоминание на экране и в чате каждые N секунд
 *  - сессия: после входа по паролю игрок заходит без /l несколько дней
 *  - точки регистрации и авторизации (/authset), после входа игрок возвращается туда, где стоял
 */
public final class InterAuth extends JavaPlugin implements Listener, CommandExecutor {

    private static final int ITERATIONS = 120_000;
    private static final Set<String> ALLOWED_COMMANDS = Set.of("reg", "register", "l", "login");

    private final Set<UUID> logged = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<UUID, BukkitTask> timers = new ConcurrentHashMap<>();
    private final Map<UUID, BossBar> bars = new ConcurrentHashMap<>();
    private final Map<UUID, Location> origins = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private File dataFile;
    private YamlConfiguration data;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        if (!getDataFolder().exists()) getDataFolder().mkdirs();
        dataFile = new File(getDataFolder(), "data.yml");
        data = YamlConfiguration.loadConfiguration(dataFile);

        Bukkit.getPluginManager().registerEvents(this, this);
        for (String c : List.of("reg", "l", "cp", "authset", "authreset", "authreload")) {
            Objects.requireNonNull(getCommand(c)).setExecutor(this);
        }
        // на случай /reload — обработать тех, кто уже на сервере
        for (Player p : Bukkit.getOnlinePlayers()) beginSession(p);
    }

    @Override
    public void onDisable() {
        for (Player p : Bukkit.getOnlinePlayers()) {
            stopTimer(p);
            Location back = origins.remove(p.getUniqueId());
            if (back != null && !authed(p)) p.teleport(back);
        }
    }

    // ---------- хранилище / хеш ----------

    private String key(Player p) {
        return p.getName().toLowerCase(Locale.ROOT);
    }

    private boolean isRegistered(Player p) {
        return data.contains("users." + key(p) + ".hash");
    }

    private String hash(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256);
        byte[] h = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(h);
    }

    private void store(Player p, String password) throws Exception {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        data.set("users." + key(p) + ".salt", Base64.getEncoder().encodeToString(salt));
        data.set("users." + key(p) + ".hash", hash(password, salt));
        save();
    }

    private boolean check(Player p, String password) {
        try {
            String s = data.getString("users." + key(p) + ".salt");
            String h = data.getString("users." + key(p) + ".hash");
            if (s == null || h == null) return false;
            String test = hash(password, Base64.getDecoder().decode(s));
            return MessageDigest.isEqual(test.getBytes(), h.getBytes());
        } catch (Exception e) {
            return false;
        }
    }

    private synchronized void save() {
        try {
            data.save(dataFile);
        } catch (IOException e) {
            getLogger().severe("Не удалось сохранить data.yml: " + e.getMessage());
        }
    }

    // ---------- сообщения ----------

    private Component comp(String key, String... kv) {
        String s = getConfig().getString("messages." + key, "&c[" + key + "]");
        for (int i = 0; i + 1 < kv.length; i += 2) s = s.replace(kv[i], kv[i + 1]);
        return LegacyComponentSerializer.legacyAmpersand().deserialize(s);
    }

    private void send(Player p, String key, String... kv) {
        p.sendMessage(comp(key, kv));
    }

    private boolean authed(Player p) {
        return logged.contains(p.getUniqueId());
    }

    // ---------- сессия (раз в несколько дней) ----------

    private long sessionMs() {
        return getConfig().getLong("session-hours", 72) * 3_600_000L;
    }

    private String ipOf(Player p) {
        return p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "";
    }

    private boolean sessionValid(Player p) {
        long last = data.getLong("users." + key(p) + ".last-login", 0L);
        if (last <= 0L) return false;
        if (System.currentTimeMillis() - last > sessionMs()) return false;
        if (getConfig().getBoolean("check-ip", true)) {
            String ip = data.getString("users." + key(p) + ".ip");
            if (ip == null || !ip.equals(ipOf(p))) return false;
        }
        return true;
    }

    private String leftText(Player p) {
        long last = data.getLong("users." + key(p) + ".last-login", 0L);
        long ms = sessionMs() - (System.currentTimeMillis() - last);
        long h = Math.max(1L, ms / 3_600_000L);
        long d = h / 24L;
        long hh = h % 24L;
        return d > 0 ? d + " д. " + hh + " ч." : hh + " ч.";
    }

    // ---------- точки регистрации / авторизации ----------

    private Location room(boolean registered) {
        try {
            Location l = data.getLocation("locations." + (registered ? "login" : "reg"));
            return (l != null && l.getWorld() != null) ? l : null;
        } catch (Exception e) {
            return null;
        }
    }

    private Location pending(Player p) {
        try {
            Location l = data.getLocation("pending." + key(p));
            return (l != null && l.getWorld() != null) ? l : null;
        } catch (Exception e) {
            return null;
        }
    }

    // ---------- вход игрока ----------

    private void beginSession(Player p) {
        UUID id = p.getUniqueId();
        logged.remove(id);
        attempts.remove(id);
        stopTimer(p);

        boolean registered = isRegistered(p);
        Location pend = pending(p);

        // Сессия ещё действует — пускаем без пароля, телепорта нет
        if (registered && sessionValid(p)) {
            logged.add(id);
            if (pend != null) {
                p.teleport(pend); // вернуть, если в прошлый раз вышли в комнате авторизации
            }
            if (data.contains("pending." + key(p))) {
                data.set("pending." + key(p), null);
                save();
            }
            send(p, "session-restored", "%left%", leftText(p));
            return;
        }

        // Нужна регистрация или /l
        Location room = room(registered);
        if (room != null) {
            Location origin = pend != null ? pend : p.getLocation();
            origins.put(id, origin);
            data.set("pending." + key(p), origin);
            save();
            p.teleport(room);
        }
        startTimer(p, registered);
    }

    private void finishAuth(Player p, String messageKey) {
        UUID id = p.getUniqueId();
        logged.add(id);
        attempts.remove(id);
        stopTimer(p);
        p.clearTitle();

        String k = key(p);
        data.set("users." + k + ".last-login", System.currentTimeMillis());
        data.set("users." + k + ".ip", ipOf(p));
        data.set("pending." + k, null);
        save();

        Location back = origins.remove(id);
        if (back != null && back.getWorld() != null) p.teleport(back); // туда, где игрок стоял
        send(p, messageKey);
    }

    // ---------- таймер и напоминания ----------

    private void startTimer(Player p, boolean registered) {
        stopTimer(p);
        UUID id = p.getUniqueId();
        int total = Math.max(5, getConfig().getInt(registered ? "login-timeout" : "register-timeout", 45));
        int interval = Math.max(1, getConfig().getInt("reminder-interval", 5));

        BossBar bar = BossBar.bossBar(Component.empty(), 1.0f, BossBar.Color.YELLOW, BossBar.Overlay.PROGRESS);
        p.showBossBar(bar);
        bars.put(id, bar);

        int[] left = {total};
        BukkitTask task = Bukkit.getScheduler().runTaskTimer(this, () -> {
            if (!p.isOnline() || authed(p)) {
                stopTimer(p);
                return;
            }
            if (left[0] <= 0) {
                stopTimer(p);
                p.kick(comp(registered ? "kick-login" : "kick-register"));
                return;
            }
            int elapsed = total - left[0];

            bar.name(comp(registered ? "bar-login" : "bar-register", "%time%", String.valueOf(left[0])));
            bar.progress(Math.max(0f, Math.min(1f, (float) left[0] / total)));
            bar.color(left[0] <= 10 ? BossBar.Color.RED : BossBar.Color.YELLOW);

            if (elapsed % interval == 0) remind(p, registered);
            left[0]--;
        }, 0L, 20L);
        timers.put(id, task);
    }

    private void stopTimer(Player p) {
        UUID id = p.getUniqueId();
        BukkitTask t = timers.remove(id);
        if (t != null) t.cancel();
        BossBar b = bars.remove(id);
        if (b != null) p.hideBossBar(b);
    }

    /** Надпись на экране + сообщение в чат. */
    private void remind(Player p, boolean registered) {
        Component title = comp(registered ? "title-login" : "title-register");
        Component sub = comp(registered ? "subtitle-login" : "subtitle-register");
        p.showTitle(Title.title(title, sub, Title.Times.times(
                Duration.ofMillis(200), Duration.ofMillis(4200), Duration.ofMillis(400))));
        p.sendMessage(comp(registered ? "chat-login" : "chat-register"));
    }

    private void chatPrompt(Player p) {
        p.sendMessage(comp(isRegistered(p) ? "chat-login" : "chat-register"));
    }

    // ---------- команды ----------

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        String name = cmd.getName().toLowerCase(Locale.ROOT);

        // --- админ-команды (можно и из консоли) ---
        if (name.equals("authreload")) {
            if (!sender.hasPermission("interauth.admin")) {
                sender.sendMessage(comp("no-permission"));
                return true;
            }
            reloadConfig();
            sender.sendMessage(comp("reloaded"));
            return true;
        }
        if (name.equals("authreset")) {
            if (!sender.hasPermission("interauth.admin")) {
                sender.sendMessage(comp("no-permission"));
                return true;
            }
            if (args.length != 1) {
                sender.sendMessage(comp("usage-authreset"));
                return true;
            }
            String k = args[0].toLowerCase(Locale.ROOT);
            if (!data.contains("users." + k)) {
                sender.sendMessage(comp("reset-none", "%player%", args[0]));
                return true;
            }
            data.set("users." + k, null);
            save();
            sender.sendMessage(comp("reset-ok", "%player%", args[0]));
            Player t = Bukkit.getPlayerExact(args[0]);
            if (t != null) beginSession(t);
            return true;
        }

        if (!(sender instanceof Player p)) {
            sender.sendMessage(comp("only-players"));
            return true;
        }

        switch (name) {
            case "reg" -> {
                if (authed(p) || isRegistered(p)) {
                    send(p, "already-registered");
                    return true;
                }
                if (args.length != 2) {
                    send(p, "usage-reg");
                    return true;
                }
                if (!args[0].equals(args[1])) {
                    send(p, "passwords-mismatch");
                    return true;
                }
                int min = getConfig().getInt("min-password-length", 6);
                if (args[0].length() < min) {
                    send(p, "password-short", "%min%", String.valueOf(min));
                    return true;
                }
                try {
                    store(p, args[0]);
                } catch (Exception e) {
                    send(p, "error");
                    return true;
                }
                finishAuth(p, "register-ok");
            }
            case "l" -> {
                if (authed(p)) {
                    send(p, "already-logged");
                    return true;
                }
                if (!isRegistered(p)) {
                    send(p, "not-registered");
                    return true;
                }
                if (args.length != 1) {
                    send(p, "usage-login");
                    return true;
                }
                if (check(p, args[0])) {
                    finishAuth(p, "login-ok");
                } else {
                    int max = getConfig().getInt("max-attempts", 5);
                    int n = attempts.merge(p.getUniqueId(), 1, Integer::sum);
                    if (n >= max) {
                        p.kick(comp("kick-attempts"));
                    } else {
                        send(p, "wrong-password", "%n%", String.valueOf(n), "%max%", String.valueOf(max));
                    }
                }
            }
            case "cp" -> {
                if (!authed(p)) {
                    send(p, "need-login");
                    return true;
                }
                if (args.length != 2) {
                    send(p, "usage-cp");
                    return true;
                }
                if (!check(p, args[0])) {
                    send(p, "wrong-old-password");
                    return true;
                }
                int min = getConfig().getInt("min-password-length", 6);
                if (args[1].length() < min) {
                    send(p, "password-short", "%min%", String.valueOf(min));
                    return true;
                }
                try {
                    store(p, args[1]);
                    send(p, "password-changed");
                } catch (Exception e) {
                    send(p, "error");
                }
            }
            case "authset" -> {
                if (!p.hasPermission("interauth.admin")) {
                    send(p, "no-permission");
                    return true;
                }
                if (args.length < 1 || !(args[0].equalsIgnoreCase("reg") || args[0].equalsIgnoreCase("login"))) {
                    send(p, "usage-authset");
                    return true;
                }
                boolean isLogin = args[0].equalsIgnoreCase("login");
                boolean clear = args.length >= 2 && args[1].equalsIgnoreCase("clear");
                data.set("locations." + (isLogin ? "login" : "reg"), clear ? null : p.getLocation());
                save();
                if (clear) send(p, isLogin ? "loc-login-cleared" : "loc-reg-cleared");
                else send(p, isLogin ? "loc-login-set" : "loc-reg-set");
            }
            default -> {
                return false;
            }
        }
        return true;
    }

    // ---------- вход / выход ----------

    @EventHandler
    public void onJoin(PlayerJoinEvent e) {
        beginSession(e.getPlayer());
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        Player p = e.getPlayer();
        UUID id = p.getUniqueId();
        boolean wasAuthed = authed(p);
        stopTimer(p);
        Location back = origins.remove(id);
        if (!wasAuthed && back != null && back.getWorld() != null) {
            p.teleport(back); // чтобы позиция сохранилась настоящая, а не в комнате входа
        }
        logged.remove(id);
        attempts.remove(id);
    }

    // ---------- ограничения для неавторизованных ----------

    @EventHandler(priority = EventPriority.LOWEST)
    public void onMove(PlayerMoveEvent e) {
        if (authed(e.getPlayer())) return;
        if (e.getTo() == null) return;
        if (e.getFrom().getX() != e.getTo().getX()
                || e.getFrom().getY() != e.getTo().getY()
                || e.getFrom().getZ() != e.getTo().getZ()) {
            e.setTo(e.getFrom());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommandPre(PlayerCommandPreprocessEvent e) {
        if (authed(e.getPlayer())) return;
        String m = e.getMessage().toLowerCase(Locale.ROOT);
        String first = m.length() > 1 ? m.substring(1).split(" ")[0] : "";
        int colon = first.indexOf(':');
        if (colon >= 0) first = first.substring(colon + 1);
        if (!ALLOWED_COMMANDS.contains(first)) {
            e.setCancelled(true);
            chatPrompt(e.getPlayer());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onChat(AsyncChatEvent e) {
        if (!authed(e.getPlayer())) {
            e.setCancelled(true);
            chatPrompt(e.getPlayer());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onBreak(BlockBreakEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlace(BlockPlaceEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInteract(PlayerInteractEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInteractEntity(PlayerInteractEntityEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onDrop(PlayerDropItemEvent e) {
        if (!authed(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPickup(EntityPickupItemEvent e) {
        if (e.getEntity() instanceof Player p && !authed(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInvClick(InventoryClickEvent e) {
        if (e.getWhoClicked() instanceof Player p && !authed(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInvOpen(InventoryOpenEvent e) {
        if (e.getPlayer() instanceof Player p && !authed(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onDamage(EntityDamageEvent e) {
        if (e.getEntity() instanceof Player p && !authed(p)) e.setCancelled(true);
    }
}
