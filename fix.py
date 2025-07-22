import os
import re

BASE_DIR = 'content/docs/'

def fix_markdown_images(md_path):
    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Replace markdown image links with Hugo figure shortcodes
    def replacer(match):
        alt_text = match.group(1)
        img_path = match.group(2)
        filename = os.path.basename(img_path)
        return f'{{{{< figure src="{filename}" alt="{alt_text}" >}}}}'

    # Regex for markdown image: ![alt](path)
    pattern = r'!\[(.*?)\]\((.*?)\)'

    new_content = re.sub(pattern, replacer, content)

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"[+] Updated: {md_path}")

def main():
    for ctf_dir in os.listdir(BASE_DIR):
        ctf_path = os.path.join(BASE_DIR, ctf_dir)
        index_md = os.path.join(ctf_path, 'index.md')
        if os.path.isfile(index_md):
            fix_markdown_images(index_md)

if __name__ == "__main__":
    main()
