spicy_add_analyzer(
    NAME Tox
    PACKAGE_NAME Tox
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
