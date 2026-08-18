import argparse
import xml.etree.ElementTree as ET
from xml.dom import minidom


class SysmonConfigGenerator:
    DEFAULT_RULES = {
        '1': 'ProcessCreate',
        '3': 'NetworkConnect',
        '7': 'ImageLoad',
        '8': 'ThreadCreate',
        '10': 'ProcessAccess',
        '11': 'FileCreate'
    }

    def __init__(self):
        self.rules = dict(self.DEFAULT_RULES)

    def generate_config(self, enable_rules=None):
        if enable_rules is not None:
            self.rules = {k: v for k, v in self.DEFAULT_RULES.items() if k in enable_rules}

        sysmon = ET.Element('Sysmon')
        sysmon.set('schemaversion', '4.50')

        hash_filters = ET.SubElement(sysmon, 'HashAlgorithms')
        hash_filters.text = 'md5,sha256,IMPHASH'

        event_filtering = ET.SubElement(sysmon, 'EventFiltering')

        rule_map = {
            '1': {
                'onmatch': 'exclude',
                'include': [
                    {'field': 'Image', 'condition': 'is', 'value': 'C:\\Windows\\System32\\svchost.exe'},
                    {'field': 'Image', 'condition': 'is', 'value': 'C:\\Windows\\System32\\lsass.exe'},
                    {'field': 'Image', 'condition': 'is', 'value': 'C:\\Windows\\System32\\csrss.exe'}
                ]
            },
            '3': {
                'onmatch': 'include',
                'include': [
                    {'field': 'DestinationPort', 'condition': 'is', 'value': '445'},
                    {'field': 'DestinationPort', 'condition': 'is', 'value': '5985'},
                    {'field': 'DestinationPort', 'condition': 'is', 'value': '5986'}
                ]
            },
            '7': {
                'onmatch': 'exclude',
                'include': [
                    {'field': 'ImageLoaded', 'condition': 'contains', 'value': 'C:\\Windows\\System32\\'}
                ]
            },
            '8': {
                'onmatch': 'include',
                'include': [
                    {'field': 'TargetImage', 'condition': 'is not', 'value': 'C:\\Windows\\System32\\svchost.exe'}
                ]
            },
            '10': {
                'onmatch': 'include',
                'include': [
                    {'field': 'TargetImage', 'condition': 'end with', 'value': 'lsass.exe'},
                    {'field': 'GrantedAccess', 'condition': 'is', 'value': '0x1010'}
                ]
            },
            '11': {
                'onmatch': 'include',
                'include': [
                    {'field': 'TargetFilename', 'condition': 'contains', 'value': 'AppData'},
                    {'field': 'TargetFilename', 'condition': 'contains', 'value': 'Temp'},
                    {'field': 'TargetFilename', 'condition': 'end with', 'value': '.ps1'},
                    {'field': 'TargetFilename', 'condition': 'end with', 'value': '.bat'}
                ]
            }
        }

        for rule_id, rule_name in self.rules.items():
            rule_config = rule_map.get(rule_id)
            rule_elem = ET.SubElement(event_filtering, 'RuleGroup')
            rule_elem.set('groupRelation', 'or')

            process_rule = ET.SubElement(rule_elem, 'ProcessCreate' if rule_id == '1' else rule_name)
            process_rule.set('onmatch', rule_config['onmatch'] if rule_config else 'include')

            if rule_config:
                for filter_def in rule_config['include']:
                    filter_elem = ET.SubElement(process_rule, 'Rule')
                    filter_elem.set('field', filter_def['field'])
                    filter_elem.set('condition', filter_def['condition'])
                    filter_elem.set('value', filter_def['value'])

        return self._prettify(sysmon)

    def create_detection_rules(self):
        rules = {
            '1': {
                'name': 'ProcessCreate',
                'mitre_technique': 'T1059',
                'rationale': 'Monitors all new process creation to detect suspicious command lines, unusual parent-child relationships, and execution from unexpected locations'
            },
            '3': {
                'name': 'NetworkConnect',
                'mitre_technique': 'T1071',
                'rationale': 'Tracks outbound network connections to identify C2 beaconing, data exfiltration, and lateral movement via SMB/RPC'
            },
            '7': {
                'name': 'ImageLoad',
                'mitre_technique': 'T1055.004',
                'rationale': 'Captures DLL loading events to detect API hooking, DLL search order hijacking, and suspicious module loads'
            },
            '8': {
                'name': 'ThreadCreate',
                'mitre_technique': 'T1055.001',
                'rationale': 'Monitors thread creation including remote threads to detect process injection via CreateRemoteThread'
            },
            '10': {
                'name': 'ProcessAccess',
                'mitre_technique': 'T1003.001',
                'rationale': 'Tracks process access patterns to identify credential dumping attempts against LSASS and other sensitive processes'
            },
            '11': {
                'name': 'FileCreate',
                'mitre_technique': 'T1105',
                'rationale': 'Records file creation events to detect dropped malware, persistence scripts, and staged payloads'
            }
        }
        return rules

    def validate_config(self, config_path):
        try:
            tree = ET.parse(config_path)
            root = tree.getroot()
            if root.tag != 'Sysmon':
                return False, 'Root element must be Sysmon'
            schemaversion = root.get('schemaversion', '')
            if not schemaversion:
                return False, 'Missing schemaversion attribute'
            event_filtering = root.find('EventFiltering')
            if event_filtering is None:
                return False, 'Missing EventFiltering element'
            for child in event_filtering:
                if child.tag == 'RuleGroup':
                    for rule in child:
                        onmatch = rule.get('onmatch')
                        if onmatch not in ('include', 'exclude'):
                            return False, 'Invalid onmatch value: {}'.format(onmatch)
            return True, 'Configuration is valid (schema {})'.format(schemaversion)
        except ET.ParseError as e:
            return False, 'XML parse error: {}'.format(str(e))
        except FileNotFoundError:
            return False, 'File not found: {}'.format(config_path)

    def _prettify(self, elem):
        rough = ET.tostring(elem, encoding='unicode')
        parsed = minidom.parseString(rough)
        pretty = parsed.toprettyxml(indent='  ')
        lines = [line for line in pretty.split('\n') if line.strip()]
        lines.insert(1, '<!-- Generated by ETW EDR Agent Sysmon Config Generator -->')
        return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Sysmon Configuration Generator')
    parser.add_argument('--rules', nargs='+', help='Specific rule IDs to enable (e.g. 1 7 10)')
    parser.add_argument('--output', default='sysmonconfig.xml', help='Output file path')
    parser.add_argument('--validate', help='Validate an existing config file')
    parser.add_argument('--list-rules', action='store_true', help='List available detection rules')
    args = parser.parse_args()

    generator = SysmonConfigGenerator()

    if args.list_rules:
        rules = generator.create_detection_rules()
        for rule_id, info in sorted(rules.items()):
            print('Rule {} - {} ({})'.format(rule_id, info['name'], info['mitre_technique']))
            print('  {}'.format(info['rationale']))
            print()
        return

    if args.validate:
        valid, message = generator.validate_config(args.validate)
        print('VALID' if valid else 'INVALID')
        print(message)
        return

    enable_rules = args.rules
    config_xml = generator.generate_config(enable_rules=enable_rules)

    with open(args.output, 'w') as f:
        f.write(config_xml)
    print('Configuration written to {}'.format(args.output))


if __name__ == '__main__':
    main()
