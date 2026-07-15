# import module
from pdf2image import convert_from_path
from pathlib import Path

input_dir = Path("C:/Users/Marco/Desktop/Tesi Bella/Tesi-Magistrale---M.-Mecarelli-F.-Santini/Programma/pcap")
output_dir = Path("C:/Users/Marco/Desktop/Tesi Bella/Tesi-Magistrale---M.-Mecarelli-F.-Santini/Programma/pcap")
output_dir.mkdir(exist_ok=True)

for pdf_path in input_dir.glob("*.pdf"):
    pages = convert_from_path(pdf_path, dpi=300)

    for i, page in enumerate(pages, start=1):
        out_file = output_dir / f"{pdf_path.stem}_page_{i}.png"
        page.save(out_file, "PNG")