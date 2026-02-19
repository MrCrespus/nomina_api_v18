import os
import datetime
from jinja2 import Environment, FileSystemLoader


class XMLGenerator:
    def __init__(self, templates_dir=None):
        if templates_dir is None:
            # Resolve absolute path to 'templates' dir relative to this file
            # This file is in /services, so we go up one level to project root
            base_dir = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
            templates_dir = os.path.join(base_dir, 'templates')

        self.env = Environment(loader=FileSystemLoader(templates_dir))
        self.template = self.env.get_template('nomina_dian.xml')

    def render(self, data):
        if 'InformacionGeneral' in data and 'HoraGen' not in data['InformacionGeneral']:
            data['InformacionGeneral']['HoraGen'] = datetime.datetime.now().strftime(
                "%H:%M:%S")

        xml_content = self.template.render(data)
        return xml_content

    def save_to_file(self, xml_content, filename):
        output_dir = "output_xmls"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        file_path = os.path.join(output_dir, filename)
        with open(file_path, "w", encoding='utf-8') as f:
            f.write(xml_content)
        return file_path
