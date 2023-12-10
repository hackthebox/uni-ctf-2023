from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from io import BytesIO

class HTML2PDF():
    def __init__(self):
        self.stream_file = BytesIO()
        self.content = []


    def add_paragraph(self, text):
        self.content.append(Paragraph(text))


    def add_table(self, data):
        table_data = []
        table_data.append([k for k in data[0].keys()])
        for item in data:
            table_data.append([item[key] for key in item.keys()])

        table = Table(table_data)

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black)
        ]))
        self.content.append(table)


    def get_document_template(self, stream_file):
        return SimpleDocTemplate(stream_file)


    def build_document(self, document, content, **props):
        document.build(content, **props)


    def convert(self, html, data):
        doc = self.get_document_template(self.stream_file)
        self.add_paragraph(html)
        self.add_table(data)
        self.build_document(doc, self.content)
        return self.stream_file