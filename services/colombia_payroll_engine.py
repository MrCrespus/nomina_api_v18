class ColombiaPayrollEngine:
    SMMLV = 1750905
    AUX_TRANSPORTE = 200000
    UVT = 53000

    @staticmethod
    def calculate_payroll(contract, worked_days_data, overtime_hours):
        wage = contract.get('wage', 0)
        days_worked = float(worked_days_data.get('WORK100', 0))

        total_days = sum(float(x) for x in worked_days_data.values())

        pago_basico = (wage / 30) * days_worked

        pago_transporte = 0
        if wage <= (ColombiaPayrollEngine.SMMLV * 2) and days_worked > 0:
            pago_transporte = (
                ColombiaPayrollEngine.AUX_TRANSPORTE / 30) * days_worked

        valor_hora = wage / 240

        pago_hed = float(overtime_hours.get('HED', 0)) * valor_hora * 1.25
        pago_hen = float(overtime_hours.get('HEN', 0)) * valor_hora * 1.75
        pago_rnoc = float(overtime_hours.get('RNOC', 0)) * valor_hora * 0.35

        total_extras = pago_hed + pago_hen + pago_rnoc

        ibc = pago_basico + total_extras

        if total_days >= 30 and ibc < ColombiaPayrollEngine.SMMLV:
            ibc = ColombiaPayrollEngine.SMMLV

        deduccion_salud = ibc * 0.04
        deduccion_pension = ibc * 0.04

        return {
            'EXT_BASICO': round(pago_basico, 2),
            'EXT_TRANS': round(pago_transporte, 2),
            'EXT_HED': round(pago_hed, 2),
            'EXT_HEN': round(pago_hen, 2),
            'EXT_SALUD': round(deduccion_salud, 2),
            'EXT_PENSION': round(deduccion_pension, 2)
        }
