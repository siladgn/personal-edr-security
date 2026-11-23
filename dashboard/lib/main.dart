import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const EDRDashboardApp());
}

class EDRDashboardApp extends StatelessWidget {
  const EDRDashboardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Kişisel EDR Kontrol Paneli',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0B0F19),
        cardColor: const Color(0xFF161F30),
        primaryColor: const Color(0xFF10B981),
        hintColor: const Color(0xFFEF4444),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF10B981),
          secondary: Color(0xFF3B82F6),
          surface: Color(0xFF161F30),
          error: Color(0xFFEF4444),
        ),
        useMaterial3: true,
      ),
      home: const DashboardScreen(),
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  // Connection Configuration
  final String _apiUrl = "http://localhost:5000";
  Timer? _updateTimer;

  // Local State Cache
  bool _isApiOnline = false;
  bool _isLoading = true;
  
  Map<String, dynamic> _modules = {
    "cookie_shield": true,
    "sinkhole": true,
    "phishing_detector": true
  };
  
  Map<String, dynamic> _stats = {
    "blocked_threats": 0,
    "checked_urls": 0
  };
  
  List<dynamic> _logs = [];
  
  final ScrollController _logScrollController = ScrollController();

  // Scanner state
  final TextEditingController _scanPathController = TextEditingController(text: r"C:\Users\sıla\Documents\antigravity\keen-newton\test_scan");
  bool _isScanning = false;
  Map<String, dynamic>? _scanResult;

  @override
  void initState() {
    super.initState();
    // Fetch initial status and setup periodic updates
    _fetchStatus();
    _updateTimer = Timer.periodic(const Duration(milliseconds: 1500), (timer) {
      _fetchStatus();
    });
  }

  @override
  void dispose() {
    _updateTimer?.cancel();
    _logScrollController.dispose();
    _scanPathController.dispose();
    super.dispose();
  }

  Future<void> _fetchStatus() async {
    try {
      final response = await http.get(Uri.parse("$_apiUrl/api/status")).timeout(
        const Duration(seconds: 2),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (mounted) {
          setState(() {
            _modules = data["modules"];
            _stats = data["stats"];
            
            // Check if log length increased before updating and scrolling
            final bool hasNewLogs = _logs.length != data["logs"].length;
            _logs = data["logs"];
            _isApiOnline = true;
            _isLoading = false;
            
            if (hasNewLogs) {
              _scrollToBottom();
            }
          });
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isApiOnline = false;
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _toggleModule(String moduleKey, bool currentValue) async {
    final bool targetValue = !currentValue;
    
    // Optimistic UI update
    setState(() {
      _modules[moduleKey] = targetValue;
    });

    try {
      final response = await http.post(
        Uri.parse("$_apiUrl/api/modules/toggle"),
        headers: {"Content-Type": "application/json"},
        body: json.encode({
          "module": moduleKey,
          "enabled": targetValue
        }),
      ).timeout(const Duration(seconds: 2));

      if (response.statusCode != 200) {
        // Rollback on server error
        setState(() {
          _modules[moduleKey] = currentValue;
        });
        _showSnackBar("Modül değiştirilemedi. Sunucu hatası.");
      }
    } catch (e) {
      // Rollback on network/connection failure
      setState(() {
        _modules[moduleKey] = currentValue;
      });
      _showSnackBar("Bağlantı hatası: Modül durumu güncellenemedi.");
    }
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_logScrollController.hasClients) {
        _logScrollController.animateTo(
          _logScrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: const Color(0xFFEF4444),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    // Determine overall system safety state
    final bool anyModuleDisabled = _modules.values.any((val) => val == false);
    final bool isSystemSafe = _isApiOnline && !anyModuleDisabled;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            const Icon(Icons.security, color: Color(0xFF10B981)),
            const SizedBox(width: 10),
            const Text(
              'KİŞİSEL EDR',
              style: TextStyle(fontWeight: FontWeight.bold, letterSpacing: 1.2),
            ),
          ],
        ),
        backgroundColor: const Color(0xFF161F30),
        elevation: 0,
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 20),
            child: Row(
              children: [
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(
                    color: _isApiOnline ? const Color(0xFF10B981) : const Color(0xFFEF4444),
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: _isApiOnline 
                            ? const Color(0xFF10B981).withOpacity(0.5) 
                            : const Color(0xFFEF4444).withOpacity(0.5),
                        blurRadius: 6,
                        spreadRadius: 2,
                      )
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  _isApiOnline ? 'API BAĞLI' : 'BAĞLANTI YOK',
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: _isApiOnline ? const Color(0xFF10B981) : const Color(0xFFEF4444),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator(color: Color(0xFF10B981)))
          : Padding(
              padding: const EdgeInsets.all(20.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // 1. System Status Banner (Header Card)
                  _buildStatusHeader(isSystemSafe),
                  const SizedBox(height: 20),

                  // 2. Module Toggle Section (Toggles Grid/Row)
                  _buildModuleToggles(),
                  const SizedBox(height: 20),

                  // 4. Statistics Cards
                  _buildStatisticsRow(),
                  const SizedBox(height: 20),

                  // Malware Scanner Section
                  _buildMalwareScanner(),
                  const SizedBox(height: 20),

                  // 3. Live Threat Logs Terminal
                  Expanded(
                    child: _buildThreatLogsConsole(),
                  ),
                ],
              ),
            ),
    );
  }

  Widget _buildStatusHeader(bool isSystemSafe) {
    Color bannerColor = const Color(0xFF10B981);
    String title = "SİSTEM GÜVENDE";
    String description = "Tüm aktif EDR kalkanları koruma sağlıyor. Tehdit algılanmadı.";
    IconData icon = Icons.gpp_good_rounded;

    if (!_isApiOnline) {
      bannerColor = const Color(0xFF6B7280);
      title = "EDR BAĞLANTISI KESİLDİ";
      description = "Python arka plan servisi aktif değil. Güvenlik servisleri çevrimdışı.";
      icon = Icons.gpp_maybe_rounded;
    } else if (!isSystemSafe) {
      bannerColor = const Color(0xFFEF4444);
      title = "SİSTEM RİSK ALTINDA";
      description = "Bazı koruma kalkanları devre dışı bırakıldı. Bilgisayarınız savunmasız olabilir.";
      icon = Icons.gpp_bad_rounded;
    }

    return AnimatedContainer(
      duration: const Duration(milliseconds: 300),
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            bannerColor.withOpacity(0.2),
            bannerColor.withOpacity(0.05),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        border: Border.all(color: bannerColor.withOpacity(0.3), width: 1.5),
        borderRadius: BorderRadius.circular(12),
        boxShadow: [
          BoxShadow(
            color: bannerColor.withOpacity(0.05),
            blurRadius: 15,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: Row(
        children: [
          Icon(icon, size: 56, color: bannerColor),
          const SizedBox(width: 20),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 22,
                    fontWeight: FontWeight.bold,
                    color: bannerColor,
                    letterSpacing: 1.1,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  description,
                  style: const TextStyle(
                    fontSize: 14,
                    color: Color(0xFF9CA3AF),
                    height: 1.4,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildModuleToggles() {
    return Row(
      children: [
        Expanded(
          child: _buildToggleCard(
            title: "Çerez Kalkanı",
            subtitle: "Chrome yetkisiz erişim koruması",
            moduleKey: "cookie_shield",
            icon: Icons.cookie_outlined,
          ),
        ),
        const SizedBox(width: 15),
        Expanded(
          child: _buildToggleCard(
            title: "DNS Sinkhole",
            subtitle: "Zararlı IP/Domain yönlendirmesi",
            moduleKey: "sinkhole",
            icon: Icons.dns_outlined,
          ),
        ),
        const SizedBox(width: 15),
        Expanded(
          child: _buildToggleCard(
            title: "ML Oltalama Kalkanı",
            subtitle: "URL yapay zeka analiz koruması",
            moduleKey: "phishing_detector",
            icon: Icons.psychology_outlined,
          ),
        ),
      ],
    );
  }

  Widget _buildToggleCard({
    required String title,
    required String subtitle,
    required String moduleKey,
    required IconData icon,
  }) {
    final bool isEnabled = _modules[moduleKey] ?? false;
    final Color activeColor = const Color(0xFF10B981);
    final Color inactiveColor = const Color(0xFF6B7280);

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF161F30),
        border: Border.all(
          color: isEnabled 
              ? activeColor.withOpacity(0.3) 
              : Colors.transparent,
        ),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        children: [
          Icon(
            icon, 
            size: 32, 
            color: isEnabled ? activeColor : inactiveColor
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  title,
                  style: const TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  subtitle,
                  style: const TextStyle(
                    fontSize: 11,
                    color: Color(0xFF9CA3AF),
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          Switch(
            value: isEnabled,
            activeColor: activeColor,
            onChanged: _isApiOnline 
                ? (val) => _toggleModule(moduleKey, isEnabled) 
                : null,
          ),
        ],
      ),
    );
  }

  Widget _buildStatisticsRow() {
    return Row(
      children: [
        Expanded(
          child: _buildStatCard(
            title: "ENGELLENEN TEHDİTLER",
            value: _stats["blocked_threats"].toString(),
            icon: Icons.shield_outlined,
            color: const Color(0xFFEF4444),
          ),
        ),
        const SizedBox(width: 20),
        Expanded(
          child: _buildStatCard(
            title: "TARANAN URL ADRESLERİ",
            value: _stats["checked_urls"].toString(),
            icon: Icons.find_in_page_outlined,
            color: const Color(0xFF3B82F6),
          ),
        ),
      ],
    );
  }

  Widget _buildStatCard({
    required String title,
    required String value,
    required IconData icon,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      decoration: BoxDecoration(
        color: const Color(0xFF161F30),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                title,
                style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  color: Color(0xFF9CA3AF),
                  letterSpacing: 0.8,
                ),
              ),
              const SizedBox(height: 6),
              Text(
                value,
                style: const TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, size: 28, color: color),
          ),
        ],
      ),
    );
  }

  Widget _buildThreatLogsConsole() {
    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF0D131F),
        border: Border.all(color: const Color(0xFF1F2937)),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Console Header Bar
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            decoration: const BoxDecoration(
              color: Color(0xFF161F30),
              borderRadius: BorderRadius.only(
                topLeft: Radius.circular(9),
                topRight: Radius.circular(9),
              ),
            ),
            child: Row(
              children: [
                Container(
                  width: 8,
                  height: 8,
                  decoration: const BoxDecoration(color: Color(0xFFEF4444), shape: BoxShape.circle),
                ),
                const SizedBox(width: 6),
                Container(
                  width: 8,
                  height: 8,
                  decoration: const BoxDecoration(color: Color(0xFFF59E0B), shape: BoxShape.circle),
                ),
                const SizedBox(width: 6),
                Container(
                  width: 8,
                  height: 8,
                  decoration: const BoxDecoration(color: Color(0xFF10B981), shape: BoxShape.circle),
                ),
                const SizedBox(width: 15),
                const Text(
                  "CANLI TEHDİT AKIŞI (LIVE THREAT LOGS)",
                  style: TextStyle(
                    fontFamily: "monospace",
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                    color: Color(0xFF9CA3AF),
                  ),
                ),
                const Spacer(),
                const Icon(Icons.terminal, size: 16, color: Color(0xFF9CA3AF)),
              ],
            ),
          ),
          // Console Logs Output Area
          Expanded(
            child: _logs.isEmpty
                ? const Center(
                    child: Text(
                      "Konsol temiz. Bekleyen log bulunmuyor...",
                      style: TextStyle(
                        fontFamily: "monospace",
                        color: Color(0xFF6B7280),
                        fontSize: 13,
                      ),
                    ),
                  )
                : Scrollbar(
                    controller: _logScrollController,
                    thumbVisibility: true,
                    child: ListView.builder(
                      controller: _logScrollController,
                      padding: const EdgeInsets.all(12),
                      itemCount: _logs.length,
                      itemBuilder: (context, index) {
                        final log = _logs[index];
                        final String level = log["level"] ?? "info";
                        
                        // Select color based on log warning level
                        Color logColor = Colors.white70;
                        if (level == "warning") {
                          logColor = const Color(0xFFF59E0B); // Amber warning
                        } else if (level == "error") {
                          logColor = const Color(0xFFEF4444); // Red alert
                        } else if (level == "info") {
                          logColor = const Color(0xFF10B981); // Emerald system information
                        }

                        return Padding(
                          padding: const EdgeInsets.symmetric(vertical: 4),
                          child: RichText(
                            text: TextSpan(
                              style: const TextStyle(
                                fontFamily: "monospace",
                                fontSize: 12,
                                height: 1.3,
                              ),
                              children: [
                                TextSpan(
                                  text: "[${log['timestamp']}] ",
                                  style: const TextStyle(color: Color(0xFF6B7280)),
                                ),
                                TextSpan(
                                  text: "[${log['module']}] ",
                                  style: const TextStyle(
                                    color: Color(0xFF3B82F6),
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                                TextSpan(
                                  text: log['message'],
                                  style: TextStyle(color: logColor),
                                ),
                              ],
                            ),
                          ),
                        );
                      },
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  Future<void> _startScan() async {
    final String path = _scanPathController.text.trim();
    if (path.isEmpty) {
      _showSnackBar("Lütfen taranacak bir klasör veya dosya yolu girin.");
      return;
    }
    setState(() {
      _isScanning = true;
      _scanResult = null;
    });
    try {
      final response = await http.post(
        Uri.parse("$_apiUrl/api/scan"),
        headers: {"Content-Type": "application/json"},
        body: json.encode({"path": path}),
      ).timeout(const Duration(minutes: 5));

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        setState(() {
          _scanResult = data;
          _isScanning = false;
        });
        _fetchStatus();
      } else {
        final errorData = json.decode(response.body);
        _showSnackBar("Tarama hatası: ${errorData['error'] ?? 'Bilinmeyen hata'}");
        setState(() {
          _isScanning = false;
        });
      }
    } catch (e) {
      _showSnackBar("Bağlantı hatası: Tarama başlatılamadı.");
      setState(() {
        _isScanning = false;
      });
    }
  }

  Widget _buildMalwareScanner() {
    final Color activeColor = const Color(0xFF3B82F6);
    final Color errorColor = const Color(0xFFEF4444);
    final Color successColor = const Color(0xFF10B981);
    
    final bool hasThreats = _scanResult != null && (_scanResult!["threats_count"] ?? 0) > 0;
    final int scannedCount = _scanResult?["scanned_count"] ?? 0;
    final int threatsCount = _scanResult?["threats_count"] ?? 0;
    final List<dynamic> threats = _scanResult?["threats"] ?? [];

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF161F30),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Icon(Icons.biotech, color: activeColor, size: 28),
              const SizedBox(width: 10),
              Text(
                "Zararlı Yazılım Tarayıcı (Malware Scanner)",
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                  color: activeColor,
                  letterSpacing: 0.5,
                ),
              ),
            ],
          ),
          const SizedBox(height: 15),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _scanPathController,
                  decoration: InputDecoration(
                    hintText: "Taranacak klasör veya dosya yolu...",
                    filled: true,
                    fillColor: const Color(0xFF080C14),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8),
                      borderSide: const BorderSide(color: Color(0xFF233554)),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8),
                      borderSide: BorderSide(color: activeColor),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              ElevatedButton(
                onPressed: _isApiOnline && !_isScanning ? _startScan : null,
                style: ElevatedButton.styleFrom(
                  backgroundColor: activeColor,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
                child: _isScanning
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                      )
                    : const Text(
                        "Taramayı Başlat",
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
              ),
            ],
          ),
          if (_isScanning) ...[
            const SizedBox(height: 15),
            const LinearProgressIndicator(color: Color(0xFF3B82F6), backgroundColor: Color(0xFF1F2937)),
            const SizedBox(height: 8),
            const Text(
              "Dosyalar analiz ediliyor, lütfen bekleyin...",
              textAlign: TextAlign.center,
              style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 12),
            ),
          ],
          if (!_isScanning && _scanResult != null) ...[
            const SizedBox(height: 15),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFF080C14),
                border: Border.all(color: const Color(0xFF233554)),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        "Taranan Dosya: $scannedCount",
                        style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                      ),
                      Text(
                        hasThreats ? "$threatsCount Tehdit Bulundu!" : "Temiz (Tehdit Algılanmadı)",
                        style: TextStyle(
                          color: hasThreats ? errorColor : successColor,
                          fontWeight: FontWeight.bold,
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                  if (hasThreats) ...[
                    const Divider(color: Color(0xFF233554), height: 16),
                    ConstrainedBox(
                      constraints: const BoxConstraints(maxHeight: 150),
                      child: ListView.builder(
                        shrinkWrap: true,
                        itemCount: threats.length,
                        itemBuilder: (context, index) {
                          final threat = threats[index];
                          final reasons = (threat["reasons"] as List<dynamic>?)?.join(", ") ?? "";
                          return Padding(
                            padding: const EdgeInsets.symmetric(vertical: 4),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  "⚠️ Zararlı Yazılım Deseni: ${threat["file_name"]}",
                                  style: TextStyle(color: errorColor, fontWeight: FontWeight.bold, fontSize: 12),
                                ),
                                Text(
                                  "Yol: ${threat["file_path"]}",
                                  style: const TextStyle(color: Color(0xFF9CA3AF), fontSize: 11),
                                ),
                                Text(
                                  "Nedeni: $reasons",
                                  style: const TextStyle(color: Color(0xFFF59E0B), fontSize: 12),
                                ),
                                Text(
                                  "SHA-256: ${threat["hash"]}",
                                  style: const TextStyle(color: Color(0xFF6B7280), fontFamily: "monospace", fontSize: 10),
                                ),
                                const Divider(color: Color(0xFF1F2937), height: 10),
                              ],
                            ),
                          );
                        },
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }
}
