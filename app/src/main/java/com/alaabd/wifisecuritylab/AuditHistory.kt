package com.alaabd.wifisecuritylab

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

data class AuditSnapshot(
    val id: Long,
    val scannedAt: String,
    val networkCount: Int,
    val highRiskCount: Int
)

/** Local-only audit history. No network identifiers or passwords are uploaded. */
class AuditHistoryStore(context: Context) :
    SQLiteOpenHelper(context.applicationContext, "wifi_security_audits.db", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE audit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                network_count INTEGER NOT NULL,
                high_risk_count INTEGER NOT NULL
            )""".trimIndent()
        )
        db.execSQL("CREATE INDEX idx_audit_history_scanned_at ON audit_history(scanned_at DESC)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Version 1 has no prior schema to migrate from.
    }

    fun saveSnapshot(findings: List<WifiFinding>, scannedAt: String): Long {
        val values = ContentValues().apply {
            put("scanned_at", scannedAt)
            put("network_count", findings.size)
            put("high_risk_count", findings.count { it.risk == "حرج" || it.risk == "مرتفع" })
        }
        return writableDatabase.insertOrThrow("audit_history", null, values)
    }

    fun getRecent(limit: Int = 20): List<AuditSnapshot> {
        val safeLimit = limit.coerceIn(1, 100)
        val result = mutableListOf<AuditSnapshot>()
        readableDatabase.rawQuery(
            "SELECT id, scanned_at, network_count, high_risk_count FROM audit_history ORDER BY id DESC LIMIT ?",
            arrayOf(safeLimit.toString())
        ).use { cursor ->
            while (cursor.moveToNext()) {
                result += AuditSnapshot(
                    id = cursor.getLong(0),
                    scannedAt = cursor.getString(1),
                    networkCount = cursor.getInt(2),
                    highRiskCount = cursor.getInt(3)
                )
            }
        }
        return result
    }
}
