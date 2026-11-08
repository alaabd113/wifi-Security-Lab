package com.alaabd.wifisecuritylab

/**
 * Offline reference catalogue for router identification.
 *
 * A model match is an identification hint, not proof of a vulnerability or WPS state.
 * Firmware revisions vary; users must verify security settings in the router admin UI.
 */
data class RouterProfile(
    val vendor: String,
    val model: String,
    val aliases: List<String>,
    val auditNotes: List<String>
)

private val routerProfiles = listOf(
    RouterProfile(
        vendor = "NETIS",
        model = "NC21",
        aliases = listOf("NC21", "NETIS NC21"),
        auditNotes = listOf(
            "تأكد من رقم Hardware Version وإصدار Firmware قبل اعتماد أي نتيجة.",
            "تحقق يدوياً من تعطيل WPS ومن استخدام WPA2-AES أو WPA3 إن كان مدعوماً.",
            "لا توجد في هذا التطبيق نتيجة تؤكد وجود ثغرة أو PIN افتراضي لهذا الطراز."
        )
    ),
    RouterProfile(
        vendor = "TP-Link",
        model = "Archer series",
        aliases = listOf("ARCHER", "TP-LINK ARCHER", "TPLINK ARCHER"),
        auditNotes = listOf(
            "سلسلة Archer تضم إصدارات عتادية وبرمجية متعددة؛ حدّد رقم Hardware Version.",
            "راجع صفحة WPS وFirmware في لوحة الإدارة، ولا تفترض أن كل إصدارات السلسلة متطابقة."
        )
    ),
    RouterProfile(
        vendor = "TP-Link",
        model = "TL-WR series",
        aliases = listOf("TL-WR", "TP-LINK TL-WR", "TPLINK TL-WR"),
        auditNotes = listOf(
            "تحقق من رقم الطراز الكامل وإصدار Hardware/Firmware؛ أسماء السلسلة وحدها غير كافية.",
            "افحص إعداد WPS والتشفير من لوحة الإدارة."
        )
    ),
    RouterProfile(
        vendor = "D-Link",
        model = "DIR series",
        aliases = listOf("DIR-", "D-LINK DIR", "DLINK DIR"),
        auditNotes = listOf(
            "تختلف إعدادات الأمان حسب طراز DIR والمراجعة العتادية والمنطقة.",
            "تحقق من إصدار Firmware وحالة WPS والتشفير من لوحة الإدارة."
        )
    )
)

/** Returns a conservative catalogue match; never infers an exploit or default credential. */
fun findRouterProfile(input: String): RouterProfile? {
    val normalized = input.trim().uppercase()
        .replace(Regex("[^A-Z0-9]+"), " ")
        .trim()
    if (normalized.isBlank()) return null

    return routerProfiles.firstOrNull { profile ->
        profile.aliases.any { alias ->
            val key = alias.uppercase().replace(Regex("[^A-Z0-9]+"), " ").trim()
            normalized.contains(key)
        }
    }
}
