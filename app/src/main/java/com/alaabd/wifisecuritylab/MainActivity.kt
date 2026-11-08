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
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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
        "SAE" in c || "WPA3" in c -> "WPA3 (advertised)"
        "WPA2" in c || "RSN" in c -> "WPA2 / RSN (advertised)"
        "WPA" in c -> "WPA (legacy)"
        "WEP" in c -> "WEP (obsolete)"
        else -> "Open / unknown"
    }
    val (risk, advice) = when {
        "WEP" in c -> "Critical" to "WEP is obsolete. Replace it with WPA2-AES or WPA3."
        "WPA" in c && "WPA2" !in c && "RSN" !in c -> "High" to "Legacy WPA detected. Upgrade router security."
        "SAE" in c || "WPA3" in c -> "Lower" to "WPA3 is advertised. Use a strong unique passphrase and current firmware."
        "WPA2" in c || "RSN" in c -> "Moderate" to "Use WPA2-AES only or WPA3, disable WPS in router settings, and update firmware."
        else -> "High" to "Open or unrecognized security. Verify router settings and enable modern encryption."
    }
    return WifiFinding(
        ssid = result.SSID.ifBlank { "(hidden SSID)" },
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
    var status by remember { mutableStateOf("Ready. Grant permissions and scan your authorized lab.") }
    var scanning by remember { mutableStateOf(false) }
    var routerModel by remember { mutableStateOf("NETIS NC21 · HW V2 · FW V4.0") }
    var labNotes by remember { mutableStateOf("Owned / authorized lab router") }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { result ->
        if (result.values.all { it }) {
            status = "Permissions granted. Tap Scan nearby networks."
        } else {
            status = "Permission denied. Android requires location permission to expose Wi-Fi scan results."
        }
    }

    fun scan() {
        if (!hasScanPermissions(context)) {
            permissionLauncher.launch(requiredPermissions())
            return
        }
        if (!wifi.isWifiEnabled) {
            status = "Wi-Fi is off. Turn it on, then scan again."
            return
        }
        scanning = true
        status = "Requesting scan. Android may throttle scans; cached results may be returned."
        @Suppress("DEPRECATION")
        val accepted = try { wifi.startScan() } catch (_: SecurityException) { false }
        scope.launch {
            delay(if (accepted) 2200 else 500)
            try {
                @Suppress("DEPRECATION")
                val list = wifi.scanResults.orEmpty()
                    .distinctBy { it.BSSID }
                    .sortedByDescending { it.level }
                    .map { analyze(it) }
                findings = list
                status = if (list.isEmpty()) {
                    "No scan results. Check Location services, permissions, and Wi-Fi; Android/OEM scan throttling may apply."
                } else {
                    "Found ${list.size} access point(s). Results are from Android's Wi-Fi scan API."
                }
            } catch (_: SecurityException) {
                status = "Android denied scan results. Re-check app permissions."
            } finally {
                scanning = false
            }
        }
    }

    fun shareReport() {
        val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())
        val body = buildString {
            appendLine("WIFI SECURITY LAB — AUTHORIZED ASSESSMENT")
            appendLine("Date: $stamp")
            appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL} / Android ${Build.VERSION.RELEASE}")
            appendLine("Lab router: $routerModel")
            appendLine("Scope: $labNotes")
            appendLine()
            appendLine("WPS PIN audit: NOT TESTED — Android public scan API does not expose reliable WPS PIN state.")
            appendLine("No PIN guessing, password guessing, deauthentication, or unauthorized access attempts are performed.")
            appendLine()
            findings.forEachIndexed { i, f ->
                appendLine("${i + 1}. ${f.ssid} (${f.bssid})")
                appendLine("   Security: ${f.security}; risk: ${f.risk}")
                appendLine("   Frequency: ${f.frequency} MHz; signal: ${f.level} dBm")
                appendLine("   Capabilities: ${f.capabilities}")
                appendLine("   Advice: ${f.advice}")
                appendLine("   WPS: unknown from Android scan data")
                appendLine()
            }
            appendLine("Limitations: scan results can be cached/throttled and may omit hidden or unsupported details.")
        }
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "WiFi Security Lab report")
            putExtra(Intent.EXTRA_TEXT, body)
        }
        context.startActivity(Intent.createChooser(intent, "Share assessment report"))
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFFFFC857),
            secondary = Color(0xFF49C6E5),
            background = Color(0xFF080D18),
            surface = Color(0xFF121B2B)
        )
    ) {
        Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF080D18)) {
            Column(Modifier.fillMaxSize().padding(16.dp)) {
                Text("WIFI SECURITY LAB", color = Color(0xFFFFC857), fontSize = 23.sp, fontWeight = FontWeight.Black)
                Text("Authorized Wi-Fi assessment · No Root", color = Color(0xFF9DB0C8), fontSize = 13.sp)
                Spacer(Modifier.height(14.dp))
                Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF121B2B))) {
                    Column(Modifier.padding(14.dp)) {
                        Text("LAB DEVICE PROFILE", color = Color(0xFF49C6E5), fontWeight = FontWeight.Bold)
                        OutlinedTextField(
                            value = routerModel,
                            onValueChange = { routerModel = it },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Router / model / hardware / firmware") },
                            singleLine = false
                        )
                        OutlinedTextField(
                            value = labNotes,
                            onValueChange = { labNotes = it },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Authorization / lab notes") },
                            singleLine = true
                        )
                        Text("WPS: Not exposed reliably by Android scan APIs. Verify it in the router admin page.", color = Color(0xFFFFC857), fontSize = 12.sp)
                    }
                }
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Button(onClick = { scan() }, enabled = !scanning) {
                        Text(if (scanning) "Scanning…" else "Scan Wi-Fi")
                    }
                    OutlinedButton(onClick = { shareReport() }, enabled = findings.isNotEmpty()) {
                        Text("Export report")
                    }
                    OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)) }) {
                        Text("Location")
                    }
                }
                Text(status, color = Color(0xFFB7C7D9), fontSize = 12.sp, modifier = Modifier.padding(vertical = 10.dp))
                Divider(color = Color(0xFF26364D))
                Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("DISCOVERED NETWORKS", color = Color(0xFFFFC857), fontWeight = FontWeight.Bold)
                    Text("${findings.size} found", color = Color(0xFF9DB0C8))
                }
                if (findings.isEmpty()) {
                    Spacer(Modifier.height(20.dp))
                    Text("No results yet. Scan while connected to or near your authorized test router.", color = Color(0xFF9DB0C8))
                } else {
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(9.dp)) {
                        items(findings, key = { it.bssid }) { f ->
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                colors = CardDefaults.cardColors(containerColor = Color(0xFF121B2B))
                            ) {
                                Column(Modifier.padding(13.dp)) {
                                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text(f.ssid, color = Color.White, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                                        Text(f.risk.uppercase(), color = when (f.risk) {
                                            "Critical", "High" -> Color(0xFFFF7373)
                                            "Moderate" -> Color(0xFFFFC857)
                                            else -> Color(0xFF7ED6A5)
                                        }, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                                    }
                                    Text(f.bssid, color = Color(0xFF9DB0C8), fontSize = 11.sp)
                                    Text("${f.security} · ${f.frequency} MHz · ${f.level} dBm", color = Color(0xFF49C6E5), fontSize = 12.sp)
                                    Text("WPS: Unknown (not reported by Android)", color = Color(0xFFFFC857), fontSize = 11.sp)
                                    Text(f.advice, color = Color(0xFFCFD9E5), fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
