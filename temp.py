import os
import frontmatter
import yaml

# Adjusted paths for running from Lotus/
ASTRO_PROJECTS_DIR = '../Astro/src/content/projects'
ASTRO_WORK_DIR = '../Astro/src/content/work'

HUGO_PROJECTS_DIR = './content/projects'
HUGO_WORK_DIR = './content/work'

def convert_project(slug, src_path, dest_dir):
    post = frontmatter.load(src_path)

    hugo_frontmatter = {
        'title': post.get('title', slug.replace('-', ' ').title()),
        'date': post.get('date', None),
        'description': post.get('description', None),
        'tags': post.get('tags', []),
        'draft': post.get('draft', False),
    }

    hugo_frontmatter = {k: v for k, v in hugo_frontmatter.items() if v is not None}

    dest_path = os.path.join(dest_dir, f"{slug}.md")
    os.makedirs(dest_dir, exist_ok=True)

    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write('---\n')
        yaml.dump(hugo_frontmatter, f, default_flow_style=False, sort_keys=False)
        f.write('---\n\n')
        f.write(post.content)

    print(f"[+] Converted {slug} -> {dest_path}")

def migrate_projects():
    for project in os.listdir(ASTRO_PROJECTS_DIR):
        project_dir = os.path.join(ASTRO_PROJECTS_DIR, project)
        index_md = os.path.join(project_dir, 'index.md')

        if os.path.isfile(index_md):
            convert_project(project, index_md, HUGO_PROJECTS_DIR)

def migrate_work():
    for file in os.listdir(ASTRO_WORK_DIR):
        if file.endswith('.md'):
            src_file = os.path.join(ASTRO_WORK_DIR, file)
            slug = os.path.splitext(file)[0]
            convert_project(slug, src_file, HUGO_WORK_DIR)

if __name__ == "__main__":
    print("[+] Migrating projects from Astro to Hugo Lotus...")
    migrate_projects()
    print("[+] Migrating work experience from Astro to Hugo Lotus...")
    migrate_work()
    print("[+] Done.")
