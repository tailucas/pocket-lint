#!/usr/bin/env python
import os
import sys

from collections import OrderedDict
from configparser import ConfigParser, InterpolationMissingOptionError, NoOptionError


FAKE_SECTION = 'FAKESECTION'


def load_config(fp):
    cfg = ConfigParser()
    cfg.optionxform = str
    # prepend with fake header
    cfg.read_file([f'[{FAKE_SECTION}]\n' + os.linesep] + fp.readlines())
    return cfg


def err(msg, code=1):
    sys.stderr.write(msg + '\n')
    exit(code)


if __name__ == "__main__":
    overlay_config = None
    if len(sys.argv) == 2 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], 'r') as fp:
            overlay_config = load_config(fp)
    config = load_config(sys.stdin)
    sections = OrderedDict()
    try:
        for section in config.sections():
            # we don't use config.items() here to avoid emitting the defaults too
            for option in config.options(section=section):
                value = None
                if overlay_config and overlay_config.has_section(section) and overlay_config.has_option(section, option):
                    value = overlay_config.get(section=section, option=option, vars=os.environ)
                if value is None:
                    value = config.get(section=section, option=option, vars=os.environ)
                # store this now
                if section not in sections:
                    sections[section] = dict()
                if option not in sections[section]:
                    sections[section][option] = dict()
                sections[section][option] = value
        if overlay_config:
            # now supplement the overlay options
            for section in overlay_config.sections():
                # we don't use config.items() here to avoid emitting the defaults too
                for option in overlay_config.options(section=section):
                    value = overlay_config.get(section=section, option=option, vars=os.environ)
                    if section not in sections:
                        sections[section] = dict()
                    if option not in sections[section]:
                        sections[section][option] = dict()
                    sections[section][option] = value
    except InterpolationMissingOptionError as e:
        err(e.message)
    except NoOptionError as e:
        section_name = "section: '{}'."
        if section == FAKE_SECTION:
            section_name = "default section."
        err(f"No option '{option}' in {section_name}", 2)
    # now output, starting with the default section
    if FAKE_SECTION in sections:
        for option, value in list(sections[FAKE_SECTION].items()):
            print(f'{option}={value}')
        del sections[FAKE_SECTION]
    # now do each section
    for section in sections:
        print(f'[{section}]')
        for option, value in list(sections[section].items()):
            print(f'{option}={value}')
