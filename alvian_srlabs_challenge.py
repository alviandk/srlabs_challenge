import json
import xmltodict


file_name = 'com.redhat.rhsa-all.xml'
file_open = open(file_name, "r", encoding = 'utf-8')
file_read = file_open.read()
as_json = json.dumps(xmltodict.parse(file_read), indent=4)
file_open.close()
json_data = json.loads(as_json)


class RedHatSecurityUpdate:

    def __init__(self, definition):
        self.definition = definition
        self.metadata = self.definition['metadata']
        self.criteria = self.definition['criteria']

    def get_title(self):
        return self.metadata['title']


    def get_fixes_cve(self):
        if 'cve' not in self.metadata['advisory'].keys():
            return []

        cve = self.metadata['advisory']['cve']
        if type(cve) == list:
            fixes_cve = [
                item['#text'] for item in cve
            ]
        else:
            fixes_cve = [cve['#text']]
        return fixes_cve


    def get_severity(self):
        return self.metadata['advisory']['severity']


    def get_affected_cpe(self):
        return self.metadata['advisory']['affected_cpe_list']['cpe']


    def get_criteria(self):
        criteria = extract_definition_criteria(self.definition)
        return criteria['criteria']

    
    def get_advisory(self):
        advisory = {
            "title": self.get_title(),
            "fixes_cve": self.get_fixes_cve(),
            "severity": self.get_severity(),
            "affected_cpe": self.get_affected_cpe(),
            "criteria": self.get_criteria(),
        }
        return advisory


def extract_definition_criteria(definition_object, index_root=0):
    dict_object = {}
    key = 'criteria'
    if '@operator' in definition_object.keys():
        key = definition_object['@operator']
    dict_object[key] = []

    if 'criteria' in definition_object.keys():
        criteria = definition_object['criteria']
        criteria_data_type = type(criteria)
        if criteria_data_type is dict:
            child_criteria = extract_definition_criteria(criteria, index_root=index_root+1)
        elif criteria_data_type is list:
            child_criteria = [extract_definition_criteria(item, index_root=index_root+1) for item in criteria]
        dict_object[key].append(child_criteria) 
    if 'criterion' in definition_object.keys():
        criterion = definition_object['criterion']
        criterion_data_type = type(criterion)
        if index_root > 1:
            if criterion_data_type is dict:
                comment = criterion['@comment']
                # comment = parse_comment(comment, index_root)
            elif criterion_data_type is list:
                comment = [item['@comment'] for item in criterion]
                # comment = [parse_comment(item['@comment'], index_root) for item in criterion]

            dict_object[key].append(comment)
    return dict_object


def parse_comment(comment, index_root):
    parsed_comment = []
    if index_root == 0:
        parsed_comment = os_name_parser(comment)
    elif index_root == 1:
        parsed_comment = os_version_parser(comment)
    elif index_root == 2:
        parsed_comment = device_name_parser(comment)
    else:
        parse_comment = [-1]
    return parsed_comment


def os_name_parser(comment):
    return [0]

def os_version_parser(comment):
    return [1]

def device_name_parser(comment):
    return [2]

advisory = []
definitions = json_data['oval_definitions']['definitions']['definition']
for definition in definitions:
    rsu = RedHatSecurityUpdate(definition)
    advisory.append(rsu.get_advisory())
    print(rsu.get_advisory())
 

with open("com.redhat.rhsa-all.json", "w") as outfile:  
    json.dump(advisory, outfile) 
