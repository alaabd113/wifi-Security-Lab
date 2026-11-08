package com.alaabd.wifisecuritylab

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Navy = Color(0xFF07111F)
private val Panel = Color(0xFF101F32)
private val Panel2 = Color(0xFF162941)
private val Gold = Color(0xFFFFC857)
private val Cyan = Color(0xFF55D6E8)
private val Muted = Color(0xFF9CB0C8)
private val Green = Color(0xFF65D6A0)
private val Red = Color(0xFFFF7777)

data class WifiFinding(
    val ssid: String,
    val bssid: String,
    val frequency: Int,
    val level: Int,
    val capabilities: String,
    val security: String,
    val risk: String,
    val advice: String
)

private enum class LabTab(val title: String, val symbol: String) {
    HOME("الرئيسية", "⌂"),
    NETWORKS("الشبكات", "◉"),
    WPS("فحص WPS", "⌁"),
    REPORT("التقارير", "▤")
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { WifiLabApp() }
    }
}

private fun requiredPermissions(): Array<String> {
    val p = mutableListOf(Manifest.permission.ACCESS_FINE_LOCATION)
    if (Build.VERSION.SDK_INT >= 33) p += Manifest.permission.NEARBY_WIFI_DEVICES
    return p.toTypedArray()
}

private fun hasScanPermissions(context: Context): Boolean =
    requiredPermissions().all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }

private fun analyze(result: ScanResult): WifiFinding {
    val caps = result.capabilities.orEmpty()
    val c = caps.uppercase(Locale.ROOT)
    val security = when {
        "SAE" in c || "WPA3" in c -> "WPA3"
        "WPA2" in c || "RSN" in c -> "WPA2"
        "WPA" in c -> "WPA"
        "WEP" in c -> "WEP"
        else -> "مفتوحة / غير معروفة"
    }
    val (risk, advice) = when {
        "WEP" in c -> "حرج" to "تشفير WEP قديم وضعيف. غيّر إعداد الراوتر إلى WPA2-AES أو WPA3."
        "WPA" in c && "WPA2" !in c && "RSN" !in c -> "مرتفع" to "تم رصد WPA القديم. حدّث إعدادات الحماية والبرنامج الثابت."
        "SAE" in c || "WPA3" in c -> "منخفض" to "WPA3 معلن. استخدم كلمة مرور قوية وحدّث الراوتر."
        "WPA2" in c || "RSN" in c -> "متوسط" to "استخدم WPA2-AES أو WPA3، عطّل WPS من لوحة الراوتر، وحدّث firmware."
        else -> "مرتفع" to "قد تكون الشبكة مفتوحة أو لم تُعرف طريقة حمايتها. تحقق من إعدادات الراوتر."
    }
    return WifiFinding(
        ssid = result.SSID.ifBlank { "شبكة مخفية" },
        bssid = result.BSSID.orEmpty(),
        frequency = result.frequency,
        level = result.level,
        capabilities = caps,
        security = security,
        risk = risk,
        advice = advice
    )
}

@Composable
private fun WifiLabApp() {
    val context = LocalContext.current
    val wifi = remember { context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager }
    val scope = rememberCoroutineScope()
    var findings by remember { mutableStateOf(emptyList<WifiFinding>()) }
    var status by remember { mutableStateOf("جاهز للفحص — اسمح بصلاحيات Wi‑Fi أولاً") }
    var scanning by remember { mutableStateOf(false) }
    var activeTab by remember { mutableStateOf(LabTab.HOME) }
    var selectedNetwork by remember { mutableStateOf<WifiFinding?>(null) }
    var lastScan by remember { mutableStateOf("لم يتم الفحص بعد") }
    var routerName by remember { mutableStateOf("") }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { result ->
        status = if (result.values.all { it }) "تم منح الصلاحيات. اضغط ابدأ الفحص." else "الصلاحيات غير مكتملة. اسمح بالوصول إلى الأجهزة القريبة والموقع."
    }

    fun scan() {
        if (!hasScanPermissions(context)) {
            permissionLauncher.launch(requiredPermissions())
            return
        }
        if (!wifi.isWifiEnabled) {
            status = "الواي فاي مغلق. فعّله ثم أعد الفحص."
            return
        }
        scanning = true
        status = "جارٍ طلب نتائج المسح من نظام Android…"
        @Suppress("DEPRECATION")
        val accepted = try { wifi.startScan() } catch (_: SecurityException) { false }
        scope.launch {
            delay(if (accepted) 2300 else 500)
            try {
                @Suppress("DEPRECATION")
                val list = wifi.scanResults.orEmpty()
                    .distinctBy { it.BSSID }
                    .sortedByDescending { it.level }
                    .map { analyze(it) }
                findings = list
                lastScan = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
                status = if (list.isEmpty()) "لم تصل نتائج. تحقق من تفعيل الموقع وصلاحيات Wi‑Fi؛ قد يقيّد Android تكرار المسح."
                    else "اكتمل المسح: تم العثور على ${list.size} شبكة."
            } catch (_: SecurityException) {
                status = "رفض Android قراءة النتائج. راجع أذونات التطبيق."
            } finally {
                scanning = false
            }
        }
    }

    fun shareReport() {
        val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())
        val body = buildString {
            appendLine("WIFI SECURITY LAB — تقرير تدقيق مصرح")
            appendLine("التاريخ: $stamp")
            appendLine("الجهاز: ${Build.MANUFACTURER} ${Build.MODEL} / Android ${Build.VERSION.RELEASE}")
            appendLine("الشبكات المكتشفة: ${findings.size}")
            appendLine("فحص WPS PIN: غير منفذ — واجهة مسح Android لا تعرض حالة WPS PIN بشكل موثوق.")
            appendLine("لا ينفذ التطبيق تخمين PIN أو كلمات المرور.")
            findings.forEachIndexed { i, f ->
                appendLine("${i + 1}. ${f.ssid} — ${f.security} — الخطر: ${f.risk}")
                appendLine("BSSID: ${f.bssid} | ${f.frequency} MHz | ${f.level} dBm")
                appendLine("التوصية: ${f.advice}")
            }
        }
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "WiFi Security Lab — تقرير الفحص")
            putExtra(Intent.EXTRA_TEXT, body)
        }
        context.startActivity(Intent.createChooser(intent, "مشاركة التقرير"))
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Gold,
            secondary = Cyan,
            background = Navy,
            surface = Panel,
            onPrimary = Navy,
            onBackground = Color.White,
            onSurface = Color.White
        )
    ) {
        Scaffold(
            containerColor = Navy,
            bottomBar = {
                NavigationBar(containerColor = Color(0xFF0B192A), contentColor = Gold) {
                    LabTab.values().forEach { tab ->
                        NavigationBarItem(
                            selected = activeTab == tab,
                            onClick = { activeTab = tab; selectedNetwork = null },
                            icon = { Text(tab.symbol, fontSize = 19.sp, fontWeight = FontWeight.Bold) },
                            label = { Text(tab.title, fontSize = 10.sp) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = Gold,
                                selectedTextColor = Gold,
                                indicatorColor = Color(0xFF26364A),
                                unselectedIconColor = Muted,
                                unselectedTextColor = Muted
                            )
                        )
                    }
                }
            }
        ) { padding ->
            Column(
                Modifier.fillMaxSize().padding(padding)
                    .background(Navy)
            ) {
                Header()
                when (activeTab) {
                    LabTab.HOME -> HomeScreen(
                        findings = findings, scanning = scanning, status = status,
                        lastScan = lastScan, onScan = { scan() },
                        onNetworks = { activeTab = LabTab.NETWORKS },
                        onWps = { activeTab = LabTab.WPS },
                        onOpenNetwork = { selectedNetwork = it; activeTab = LabTab.NETWORKS }
                    )
                    LabTab.NETWORKS -> NetworksScreen(
                        findings = findings, selected = selectedNetwork,
                        onSelect = { selectedNetwork = it },
                        onScan = { scan() }, scanning = scanning
                    )
                    LabTab.WPS -> WpsScreen(routerName = routerName, onRouterName = { routerName = it })
                    LabTab.REPORT -> ReportScreen(
                        count = findings.size, lastScan = lastScan,
                        onShare = { shareReport() }, enabled = findings.isNotEmpty()
                    )
                }
            }
        }
    }
}

@Composable
private fun Header() {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier.size(43.dp).background(Panel2, RoundedCornerShape(14.dp)),
            contentAlignment = Alignment.Center
        ) { Text("W", color = Gold, fontSize = 24.sp, fontWeight = FontWeight.Black) }
        Spacer(Modifier.width(11.dp))
        Column(Modifier.weight(1f)) {
            Text("WIFI SECURITY LAB", color = Color.White, fontWeight = FontWeight.Black, fontSize = 16.sp, letterSpacing = 1.2.sp)
            Text("مختبر أمان الشبكات اللاسلكية", color = Muted, fontSize = 11.sp)
        }
        Box(Modifier.background(Color(0xFF153B36), CircleShape).padding(horizontal = 10.dp, vertical = 6.dp)) {
            Text("NO ROOT", color = Green, fontSize = 9.sp, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun HomeScreen(
    findings: List<WifiFinding>, scanning: Boolean, status: String, lastScan: String,
    onScan: () -> Unit, onNetworks: () -> Unit, onWps: () -> Unit,
    onOpenNetwork: (WifiFinding) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 22.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = Panel),
                shape = RoundedCornerShape(23.dp)
            ) {
                Column(Modifier.fillMaxWidth().padding(19.dp)) {
                    Text("لوحة التحكم", color = Gold, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(6.dp))
                    Text("افحص شبكتك.\nافهم مستوى حمايتها.", color = Color.White, fontSize = 25.sp, lineHeight = 32.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))
                    Text("اكتشاف الشبكات القريبة وتحليل نوع التشفير ومؤشرات المخاطر.", color = Muted, fontSize = 12.sp, lineHeight = 19.sp)
                    Spacer(Modifier.height(18.dp))
                    Button(
                        onClick = onScan,
                        enabled = !scanning,
                        modifier = Modifier.fillMaxWidth().height(52.dp),
                        shape = RoundedCornerShape(15.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Gold, contentColor = Navy)
                    ) {
                        Text(if (scanning) "جارٍ الفحص…" else "⌕   ابدأ فحص الشبكات", fontSize = 15.sp, fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.height(9.dp))
                    Text(status, color = Muted, fontSize = 11.sp, lineHeight = 16.sp)
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricCard("الشبكات", findings.size.toString(), "تم اكتشافها", Modifier.weight(1f), Cyan)
                MetricCard("آخر فحص", lastScan, "وقت المسح", Modifier.weight(1f), Gold)
            }
        }
        item {
            SectionTitle("أدوات المختبر", "اختر المهمة")
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                ActionTile("الشبكات القريبة", "عرض وتحليل النتائج", "◉", Modifier.weight(1f), onNetworks)
                ActionTile("تدقيق WPS", "إرشادات فحص الراوتر", "⌁", Modifier.weight(1f), onWps)
            }
        }
        item {
            SectionTitle("آخر الشبكات المكتشفة", "اضغط لعرض التفاصيل")
        }
        if (findings.isEmpty()) {
            item { EmptyState("لا توجد نتائج حتى الآن", "ابدأ الفحص لتظهر الشبكات القريبة ومعلومات التشفير.") }
        } else {
            items(findings.take(4), key = { it.bssid }) { f ->
                NetworkCard(f, onClick = { onOpenNetwork(f) })
            }
        }
        item {
            Text("تنبيه: نتائج المسح لا تكشف كلمة مرور الشبكة ولا تثبت حالة WPS PIN.", color = Muted, fontSize = 10.sp, lineHeight = 15.sp)
        }
    }
}

@Composable
private fun MetricCard(title: String, value: String, caption: String, modifier: Modifier, accent: Color) {
    Card(modifier, colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(17.dp)) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Text(title, color = Muted, fontSize = 11.sp)
            Spacer(Modifier.height(7.dp))
            Text(value, color = accent, fontWeight = FontWeight.Black, fontSize = 21.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(caption, color = Muted, fontSize = 10.sp)
        }
    }
}

@Composable
private fun SectionTitle(title: String, subtitle: String) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 15.sp, modifier = Modifier.weight(1f))
        Text(subtitle, color = Muted, fontSize = 10.sp)
    }
}

@Composable
private fun ActionTile(title: String, subtitle: String, symbol: String, modifier: Modifier, onClick: () -> Unit) {
    Card(
        onClick = onClick, modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = Panel2),
        shape = RoundedCornerShape(17.dp)
    ) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Text(symbol, color = Gold, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            Text(subtitle, color = Muted, fontSize = 10.sp)
        }
    }
}

@Composable
private fun EmptyState(title: String, message: String) {
    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.fillMaxWidth().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text("⌕", color = Cyan, fontSize = 34.sp)
            Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            Spacer(Modifier.height(5.dp))
            Text(message, color = Muted, fontSize = 11.sp, lineHeight = 17.sp)
        }
    }
}

@Composable
private fun NetworksScreen(
    findings: List<WifiFinding>, selected: WifiFinding?,
    onSelect: (WifiFinding?) -> Unit, onScan: () -> Unit, scanning: Boolean
) {
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(Modifier.fillMaxWidth().padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("الشبكات المكتشفة", color = Color.White, fontSize = 21.sp, fontWeight = FontWeight.Bold)
                Text("${findings.size} شبكة ضمن نتائج Android", color = Muted, fontSize = 11.sp)
            }
            Button(onClick = onScan, enabled = !scanning, colors = ButtonDefaults.buttonColors(containerColor = Gold, contentColor = Navy)) {
                Text(if (scanning) "يفحص…" else "إعادة الفحص")
            }
        }
        if (findings.isEmpty()) {
            EmptyState("قائمة الشبكات فارغة", "اضغط إعادة الفحص واسمح بالصلاحيات المطلوبة.")
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(9.dp), contentPadding = PaddingValues(bottom = 20.dp)) {
                items(findings, key = { it.bssid }) { f ->
                    NetworkCard(f, onClick = { onSelect(if (selected?.bssid == f.bssid) null else f) })
                    selected?.takeIf { it.bssid == f.bssid }?.let { NetworkDetails(it) }
                }
            }
        }
    }
}

@Composable
private fun NetworkCard(f: WifiFinding, onClick: () -> Unit) {
    Card(
        onClick = onClick, modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Panel),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(f.ssid, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(f.bssid, color = Muted, fontSize = 10.sp)
                }
                RiskPill(f.risk)
            }
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                InfoPill(f.security, Cyan)
                InfoPill("${f.frequency} MHz", Muted)
                InfoPill("${f.level} dBm", Muted)
            }
        }
    }
}

@Composable
private fun RiskPill(risk: String) {
    val c = when (risk) { "حرج", "مرتفع" -> Red; "متوسط" -> Gold; else -> Green }
    Box(Modifier.background(c.copy(alpha = 0.13f), CircleShape).padding(horizontal = 10.dp, vertical = 5.dp)) {
        Text(risk, color = c, fontSize = 10.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun InfoPill(text: String, color: Color) {
    Box(Modifier.background(color.copy(alpha = 0.12f), RoundedCornerShape(8.dp)).padding(horizontal = 8.dp, vertical = 5.dp)) {
        Text(text, color = color, fontSize = 10.sp)
    }
}

@Composable
private fun NetworkDetails(f: WifiFinding) {
    Card(colors = CardDefaults.cardColors(containerColor = Panel2), shape = RoundedCornerShape(14.dp)) {
        Column(Modifier.padding(14.dp)) {
            Text("تفاصيل الشبكة", color = Gold, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            DetailLine("نوع الحماية", f.security)
            DetailLine("مستوى الإشارة", "${f.level} dBm")
            DetailLine("التردد", "${f.frequency} MHz")
            DetailLine("WPS", "غير معروف من بيانات مسح Android")
            Spacer(Modifier.height(7.dp))
            Text("التوصية الأمنية", color = Cyan, fontWeight = FontWeight.Bold, fontSize = 11.sp)
            Text(f.advice, color = Color.White, fontSize = 11.sp, lineHeight = 17.sp)
            Text("بيانات الإعلان: ${f.capabilities}", color = Muted, fontSize = 9.sp)
        }
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = Muted, fontSize = 11.sp)
        Text(value, color = Color.White, fontSize = 11.sp)
    }
}

@Composable
private fun WpsScreen(routerName: String, onRouterName: (String) -> Unit) {
    val matchedProfile = remember(routerName) { findRouterProfile(routerName) }
    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text("تدقيق WPS", color = Color.White, fontSize = 22.sp, fontWeight = FontWeight.Bold)
            Text("تحقق من إعدادات راوتر تملكه أو لديك تصريح بفحصه.", color = Muted, fontSize = 11.sp)
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF352B1B)), shape = RoundedCornerShape(17.dp)) {
                Column(Modifier.padding(16.dp)) {
                    Text("معلومة مهمة", color = Gold, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Spacer(Modifier.height(6.dp))
                    Text("لا يستطيع تطبيق Android عادي قراءة حالة WPS PIN من نتائج مسح الشبكات بشكل موثوق. لذلك لن نعرض نتيجة وهمية مثل PIN صحيح أو كلمة مرور مكتشفة.", color = Color(0xFFFFE6B0), fontSize = 11.sp, lineHeight = 18.sp)
                }
            }
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(17.dp)) {
                Column(Modifier.padding(15.dp)) {
                    Text("بيانات جهاز الاختبار", color = Cyan, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = routerName, onValueChange = onRouterName,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("اسم الراوتر / الموديل (اختياري)") },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Gold, unfocusedBorderColor = Muted,
                            focusedLabelColor = Gold, unfocusedLabelColor = Muted,
                            focusedTextColor = Color.White, unfocusedTextColor = Color.White
                        )
                    )
                }
            }
        }
        if (routerName.isNotBlank()) {
            item {
                Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(17.dp)) {
                    Column(Modifier.padding(15.dp)) {
                        Text("نتيجة مطابقة قاعدة الأجهزة", color = Cyan, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        if (matchedProfile == null) {
                            Text("لم يتم العثور على تطابق موثوق. أدخل اسم الطراز الكامل ورقم Hardware Version يدوياً.", color = Muted, fontSize = 11.sp, lineHeight = 17.sp)
                        } else {
                            Text("${matchedProfile.vendor} — ${matchedProfile.model}", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Spacer(Modifier.height(6.dp))
                            matchedProfile.auditNotes.forEach { note ->
                                Text("• $note", color = Muted, fontSize = 11.sp, lineHeight = 17.sp)
                            }
                            Spacer(Modifier.height(6.dp))
                            Text("مطابقة اسم فقط؛ ليست كشفاً عن ثغرة أو إثباتاً لحالة WPS.", color = Gold, fontSize = 10.sp)
                        }
                    }
                }
            }
        }
        item { SectionTitle("خطوات التدقيق اليدوي", "على الراوتر نفسه") }
        item { StepCard("01", "افتح لوحة تحكم الراوتر", "اتصل بشبكتك وافتح عنوان الإدارة المكتوب على ملصق الراوتر أو في دليله.") }
        item { StepCard("02", "ابحث عن WPS", "غالباً يوجد ضمن Wireless أو Wi‑Fi Protected Setup أو إعدادات الأمان.") }
        item { StepCard("03", "تحقق من حالة PIN و Push Button", "إذا كان WPS مفعّلاً، عطّله. لا تشارك PIN أو بيانات الدخول مع أي شخص.") }
        item { StepCard("04", "احفظ التغييرات وحدّث الراوتر", "استخدم WPA2-AES أو WPA3 وكلمة مرور قوية، ثم حدّث البرنامج الثابت.") }
        item {
            Text(
                "ملاحظة: إعداد WPS يتم من لوحة تحكم الراوتر؛ إعدادات Wi-Fi في الهاتف لا تعرض حالة WPS PIN بصورة موثوقة.",
                color = Muted, fontSize = 10.sp, lineHeight = 16.sp
            )
        }
    }
}

@Composable
private fun StepCard(number: String, title: String, detail: String) {
    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(15.dp)) {
        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.Top) {
            Box(Modifier.size(34.dp).background(Panel2, RoundedCornerShape(10.dp)), contentAlignment = Alignment.Center) {
                Text(number, color = Gold, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }
            Spacer(Modifier.width(11.dp))
            Column {
                Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Text(detail, color = Muted, fontSize = 11.sp, lineHeight = 17.sp)
            }
        }
    }
}

@Composable
private fun ReportScreen(count: Int, lastScan: String, onShare: () -> Unit, enabled: Boolean) {
    Column(
        Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(13.dp)
    ) {
        Text("التقارير", color = Color.White, fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Text("ملخص الفحص المحلي على هذا الجهاز.", color = Muted, fontSize = 11.sp)
        MetricCard("الشبكات المسجلة في آخر مسح", count.toString(), "شبكة", Modifier.fillMaxWidth(), Cyan)
        MetricCard("آخر عملية فحص", lastScan, "وقت التنفيذ", Modifier.fillMaxWidth(), Gold)
        Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(15.dp)) {
                Text("محتوى التقرير", color = Gold, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Spacer(Modifier.height(8.dp))
                Text("• أسماء الشبكات ونوع التشفير المعلن\n• عنوان BSSID وقوة الإشارة والتردد\n• تصنيف أولي للمخاطر والتوصيات\n• توضيح حدود فحص WPS على Android", color = Color.White, fontSize = 11.sp, lineHeight = 21.sp)
            }
        }
        Button(
            onClick = onShare, enabled = enabled,
            modifier = Modifier.fillMaxWidth().height(50.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Gold, contentColor = Navy),
            shape = RoundedCornerShape(14.dp)
        ) { Text("مشاركة تقرير الفحص", fontWeight = FontWeight.Bold) }
        Text("التقرير لا يتضمن كلمات مرور ولا PIN ولا يدّعي اختبار اختراق لم يتم تنفيذه.", color = Muted, fontSize = 10.sp, lineHeight = 16.sp)
    }
}
