import hashlib


class CuneCalculator:
    @staticmethod
    def calculate(data, pin_software="75315"):
        try:
            num_ne = str(data['NumeroSecuenciaXML']['Numero'])
            fec_gen = str(data['Periodo']['FechaGen'])
            hor_gen = str(data['InformacionGeneral']['HoraGen'])
            val_dev = f"{data['Totales']['DevengadoTotal']:.2f}"
            val_ded = f"{data['Totales']['DeduccionesTotal']:.2f}"
            val_tol = f"{data['Totales']['TotalAPagar']:.2f}"
            nit_ne = str(data['Empleador']['NIT'])
            doc_emp = str(data['Trabajador']['Documento'])
            tipo_xml = "102"
            ambiente = str(data['InformacionGeneral']['Ambiente'])

            cune_string = (
                f"{num_ne}{fec_gen}{hor_gen}"
                f"{val_dev}{val_ded}{val_tol}"
                f"{nit_ne}{doc_emp}{tipo_xml}"
                f"{pin_software}{ambiente}"
            )

            cune_hash = hashlib.sha384(cune_string.encode('utf-8')).hexdigest()
            return cune_hash

        except KeyError as e:
            print(f"Error calculando CUNE: Falta campo {e}")
            return "ERROR_CUNE"
