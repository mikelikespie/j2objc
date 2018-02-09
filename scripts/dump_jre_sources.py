import os
import re
from collections import defaultdict

JRE_EMUL_DIR = "jre_emul"
JRE_SOURCES_FILE = os.path.join(JRE_EMUL_DIR, "jre_sources.mk")

section_start = re.compile(r'(\w.*) = \\')
header_re = re.compile(r' {2}(\w.*) \\?')


def main():
    with open("jre_emul/jre_sources.mk") as f:
        dump_file(f)


def get_jre_files():
    for (dirpath, dirnames, filenames) in os.walk(JRE_EMUL_DIR):
        prefixless_dirpath = dirpath[len(JRE_EMUL_DIR) + 1:]
        for f in filenames:
            yield os.path.join(prefixless_dirpath, f)


def dump_file(f):
    all_jre_files = list(get_jre_files())

    # this makes it o(n^2), but whatever
    def find_jre_file(suffix):
        for f in all_jre_files:
            if f.endswith(suffix):
                return f

    section_name = None

    files = defaultdict(list)

    for l in f:
        l = l.rstrip()

        section_match = section_start.match(l)
        if section_match:
            section_name = section_match.group(1)

        header_match = header_re.match(l)
        if header_match:
            files[section_name].append(find_jre_file(header_match.group(1)))

    for (name, files) in sorted(files.items()):
        print name, "=", "["
        for f in sorted(files):
            print '  "{}",'.format(f)
        print "]"




if __name__ == "__main__":
    main()
