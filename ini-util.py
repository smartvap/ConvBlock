import sys
import configparser

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print('[Usage] python3 ini-util.py --read|--write <ini-path> <section-name> <option-name> [<option-value> ..].')
        sys.exit(-1)
    elif sys.argv[1] == '--read':
        config = configparser.ConfigParser(strict=False)
        config.read(sys.argv[2])
        print(config.get(sys.argv[3], sys.argv[4]))
    elif sys.argv[1] == '--write':
		# Retain annotations
        config = configparser.ConfigParser(comment_prefixes='/', allow_no_value=True, strict=False)
        config.optionxform = lambda option: option
        config.read(sys.argv[2])
        if not config.has_section(sys.argv[3]):
            config.add_section(sys.argv[3])
        optVal = sys.argv[5]
        if len(sys.argv) > 6:
            for i in range(6, len(sys.argv)):
                optVal = optVal + ' ' + sys.argv[i]
        config.set(sys.argv[3], sys.argv[4], optVal)
        # Add space_around_delimiters parameter means no spaces are allowed on both sides of the equal sign
        config.write(open(sys.argv[2], 'w'), space_around_delimiters=False)
