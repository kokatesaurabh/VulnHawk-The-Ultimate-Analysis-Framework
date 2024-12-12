import PyPDF2
from io import BytesIO
from reportlab.pdfgen import canvas

# Define a mapping of vulnerabilities to resolutions
VULNERABILITY_MAPPING = {
    "Excessive Permissions": "Review and remove unnecessary permissions.",
    "Dangerous Permissions": "Restrict dangerous permissions unless absolutely required.",
    "Exported Activities/Services": "Secure exported components or set 'exported=false'.",
    "Large APK Size": "Optimize APK size by compressing assets and removing unused resources.",
    "Large DEX Size": "Consider splitting large DEX files using multidex support."
}

# Function to merge two PDFs
def merge_pdfs(pdf1_path, pdf2_path, output_path, vulnerabilities_found, resolutions):
    merger = PyPDF2.PdfWriter()

    # Append both PDFs to the merger
    with open(pdf1_path, "rb") as f1, open(pdf2_path, "rb") as f2:
        reader1 = PyPDF2.PdfReader(f1)
        reader2 = PyPDF2.PdfReader(f2)
        
        for page in reader1.pages:
            merger.add_page(page)
        for page in reader2.pages:
            merger.add_page(page)

    # Create a new page for the vulnerabilities and resolutions report
    packet = BytesIO()
    c = canvas.Canvas(packet)
    c.drawString(30, 750, "Vulnerabilities and Resolutions:")
    y_position = 730
    for vuln, suggestion in zip(vulnerabilities_found, resolutions):
        c.drawString(30, y_position, f"{vuln}: {suggestion}")
        y_position -= 20
    c.save()

    # Move the canvas content to the PDF
    packet.seek(0)
    new_pdf = PyPDF2.PdfReader(packet)
    page = new_pdf.pages[0]

    # Add the new page with the vulnerabilities and resolutions report
    merger.add_page(page)

    # Write the final output PDF with vulnerabilities and resolutions included
    with open(output_path, "wb") as output_file:
        merger.write(output_file)
    print(f"PDFs merged into: {output_path}")

# Function to read a PDF and extract text
def read_pdf(pdf_path):
    with open(pdf_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        pdf_text = ""
        for page in reader.pages:
            pdf_text += page.extract_text()
        return pdf_text

# Function to process vulnerabilities and provide suggestions
def analyze_vulnerabilities(pdf_text):
    vulnerabilities_found = []
    suggestions = []

    for vuln, suggestion in VULNERABILITY_MAPPING.items():
        if vuln in pdf_text:
            vulnerabilities_found.append(vuln)
            suggestions.append(suggestion)

    return vulnerabilities_found, suggestions

# Example usage
if __name__ == "__main__":
    # Paths to the PDFs to merge
    pdf1_path = "C:/Users/karan/Desktop/VulnHawk/ML/pdfs/Report (1).pdf"
    pdf2_path = "C:/Users/karan/Desktop/VulnHawk/ML/pdfs/dvba.apk_report (9).pdf"
    merged_pdf_path = "merged_report_with_vulnerabilities.pdf"

    # Read and analyze the merged PDF content
    pdf_content = read_pdf(pdf1_path)  # You can read the first PDF for analyzing vulnerabilities
    vulnerabilities, resolutions = analyze_vulnerabilities(pdf_content)

    # Merge the PDFs and append the vulnerabilities and resolutions at the end
    merge_pdfs(pdf1_path, pdf2_path, merged_pdf_path, vulnerabilities, resolutions)

    print(f"Merged PDF saved as: {merged_pdf_path}")