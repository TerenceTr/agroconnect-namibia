// frontend/utils/pdfExport.js
import html2canvas from "html2canvas";
import jsPDF from "jspdf";

export async function exportDashboardToPdf(containerSelector = "#ai-dashboard-export", filename = "ai-report.pdf") {
  const node = document.querySelector(containerSelector);
  if (!node) throw new Error("Export container not found");

  // snapshot (scale up for better quality)
  const canvas = await html2canvas(node, { scale: 2, useCORS: true, logging: false });
  const imgData = canvas.toDataURL("image/png");

  const pdf = new jsPDF({
    orientation: "landscape",
    unit: "pt",
    format: [canvas.width, canvas.height],
  });

  pdf.addImage(imgData, "PNG", 0, 0, canvas.width, canvas.height);
  pdf.save(filename);
}
