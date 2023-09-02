#!/usr/bin/env python
import json
import os
import sys
import yaml

from collections import OrderedDict


def err(msg, code=1):
    sys.stderr.write(msg + '\n')
    exit(code)


def update_section(yaml_section, section_namespace, replacement):
    if len(section_namespace) == 1:
        yaml_section[section_namespace[0]] = replacement
        return
    yaml_section_name = section_namespace.pop(0)
    update_section(
        yaml_section=yaml_section[yaml_section_name],
        section_namespace=section_namespace,
        replacement=replacement)


if __name__ == "__main__":
    yaml_config = None
    yaml_section_namespace_input = None
    # read the YAML configuration file and overlay section name
    if len(sys.argv) == 3 and os.path.isfile(sys.argv[2]):
        yaml_section_namespace_input = sys.argv[1]
        with open(sys.argv[2], 'r') as fp:
            yaml_config = yaml.safe_load(fp)
    # read the overlay configuration from STDIN as JSON
    overlay_config = json.loads(sys.stdin.readline())
    # derive yaml namespace
    yaml_section_namespace = yaml_section_namespace_input.split('/')
    update_section(yaml_section=yaml_config, section_namespace=yaml_section_namespace, replacement=overlay_config)
    print(yaml.safe_dump(yaml_config))
