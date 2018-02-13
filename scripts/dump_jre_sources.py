from collections import defaultdict, OrderedDict

import os
import re

JRE_EMUL_DIR = "jre_emul"
JRE_SOURCES_FILE = os.path.join(JRE_EMUL_DIR, "jre_sources.mk")

section_start = re.compile(r'(\w.*) = \\')
empty_section = re.compile(r'(\w.*) =$')
header_re = re.compile(r'^ {2}([+\w_/.]*) ?\\?$')
var_re = re.compile(r' +\$\((\w.*)\)(?: \\)?')
one_line_var_re = re.compile(r'(\w.*) =(?: \$\(([\w_]*)\))+')
one_line_var_elements = re.compile(r' \$\(([\w_]*)\)')


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
        for jf in all_jre_files:
            if jf.endswith(suffix):
                return jf

    section_name = None

    files = OrderedDict()
    vars = OrderedDict()

    for l in f:
        l = l.rstrip()

        section_match = section_start.match(l)
        if section_match:
            section_name = section_match.group(1)
            continue


        header_match = header_re.match(l)
        if header_match:
            if section_name not in files:
                files[section_name] = []
            files[section_name].append(find_jre_file(header_match.group(1)))
            continue

        var_match = var_re.match(l)
        if var_match:
            if section_name not in vars:
                vars[section_name] = []
            vars[section_name] += one_line_var_elements.findall(l)
            continue

        one_line_var_match = one_line_var_re.match(l)

        if one_line_var_match:
            section_name = one_line_var_match.group(1)
            if section_name not in vars:
                vars[section_name] = []

            for v in one_line_var_elements.findall(l):
                vars[section_name].append(v)

            continue

        empty_section_match = empty_section.match(l)
        if empty_section_match:
            vars[empty_section_match.group(1)] = []
            continue

    for (name, fs) in files.items():
        print name, "=", "["
        for f in fs:
            print '  "{}",'.format(f)
        print "]"
        print

    for (name, vs) in vars.items():
        if vs:
            print "{} = \\\n  {}\n".format(name, " + \\\n  ".join(vs))
        else:
            print "{} = []".format(name)
        print


if __name__ == "__main__":
    main()
