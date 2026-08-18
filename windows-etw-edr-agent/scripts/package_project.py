import os
import sys
import zipfile


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.dirname(project_root)
    output_path = os.path.join(output_dir, "windows-etw-edr-agent.zip")

    excluded = {"__pycache__", ".git", "node_modules", "bin", "obj"}
    excluded_exts = {".pyc"}

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(project_root):
            dirs[:] = [d for d in dirs if d not in excluded]
            for f in files:
                if any(f.endswith(ext) for ext in excluded_exts):
                    continue
                full_path = os.path.join(root, f)
                arc_name = os.path.relpath(full_path, project_root)
                zf.write(full_path, arc_name)

    size = os.path.getsize(output_path)
    print("Package created: {} ({:.1f} KB)".format(output_path, size / 1024))


if __name__ == "__main__":
    main()
