package com.alaabd.wifisecuritylab

import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.text.Layout
import android.text.StaticLayout
import android.text.TextDirectionHeuristics
import android.text.TextPaint
import java.io.OutputStream

/** Generates a paginated, local PDF report. No network access or credentials are used. */
object PdfReportWriter {
    fun write(output: OutputStream, findings: List<WifiFinding>, generatedAt: String, device: String) {
        val document = PdfDocument()
        val pageWidth = 595
        val pageHeight = 842
        val margin = 40f
        val contentWidth = pageWidth - (margin * 2).toInt()
        val bodyPaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
            color = android.graphics.Color.rgb(35, 48, 65)
            textSize = 10.5f
            typeface = Typeface.create("sans-serif", Typeface.NORMAL)
        }
        val headingPaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
            color = android.graphics.Color.rgb(12, 35, 58)
            textSize = 15f
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
        }
        val footerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = android.graphics.Color.GRAY
            textSize = 8f
        }
        var pageNumber = 0
        var page: PdfDocument.Page? = null
        var y = 48f

        fun startPage() {
            pageNumber++
            val info = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNumber).create()
            page = document.startPage(info)
            y = 48f
            page!!.canvas.drawText("WIFI SECURITY LAB", margin, y, headingPaint)
            y += 28f
        }

        fun finishPage() {
            val current = page ?: return
            current.canvas.drawText("Authorized assessment • Local report • Page $pageNumber", margin, pageHeight - 22f, footerPaint)
            document.finishPage(current)
            page = null
        }

        fun drawParagraph(text: String, heading: Boolean = false) {
            val paint = if (heading) headingPaint else bodyPaint
            val layout = StaticLayout.Builder.obtain(text, 0, text.length, paint, contentWidth)
                .setAlignment(Layout.Alignment.ALIGN_NORMAL)
                .setTextDirection(TextDirectionHeuristics.FIRSTSTRONG_RTL)
                .setIncludePad(false)
                .setLineSpacing(2f, 1f)
                .build()
            if (page == null) startPage()
            if (y + layout.height > pageHeight - 48f) {
                finishPage()
                startPage()
            }
            page!!.canvas.save()
            page!!.canvas.translate(margin, y)
            layout.draw(page!!.canvas)
            page!!.canvas.restore()
            y += layout.height + if (heading) 10f else 7f
        }

        try {
            startPage()
            drawParagraph("تقرير تدقيق أمان شبكات Wi-Fi", true)
            drawParagraph("Generated: $generatedAt")
            drawParagraph("Device: $device")
            drawParagraph("Networks detected: ${findings.size}")
            drawParagraph("WPS PIN audit: Not performed. Android public scan APIs do not reliably expose WPS PIN status.")
            drawParagraph("This report does not contain passwords or PINs and does not claim an intrusion test.")
            drawParagraph("Network findings", true)
            if (findings.isEmpty()) {
                drawParagraph("No scan results were available when this report was generated.")
            } else {
                findings.forEachIndexed { index, finding ->
                    drawParagraph("${index + 1}. ${finding.ssid} — ${finding.security} — Risk: ${finding.risk}", true)
                    drawParagraph("BSSID: ${finding.bssid} | Frequency: ${finding.frequency} MHz | Signal: ${finding.level} dBm")
                    drawParagraph("Advertised capabilities: ${finding.capabilities.ifBlank { "Not provided" }}")
                    drawParagraph("Recommendation: ${finding.advice}")
                }
            }
        } finally {
            finishPage()
            document.writeTo(output)
            document.close()
        }
    }
}
