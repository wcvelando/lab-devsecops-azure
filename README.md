# 🔐 Lab DevSecOps Azure
## Seguridad en Cloud Services · UGR · Tecnicatura en Ciberseguridad

> **Objetivo:** Lab en Azure,
> integrando un pipeline DevSecOps completo con herramientas SAST, DAST,
> IaC scanning y policy-as-code.

---

## 📐 Arquitectura Azure (equivalencias AWS)

```
Lab                      →    Este lab (Azure)
─────────────────────────────────────────────────────
Azure Container Instances (ACI) + Flask
Azure Database for MySQL Flexible Server
Azure Virtual Network + Subnets
Network Security Groups (NSG)
Azure Key Vault
ACI con IP pública
```

## 🛠️ Stack del pipeline

| Herramienta | Tipo | OWASP cubierto |
|-------------|------|----------------|
| Gitleaks | Secrets Detection | A02 |
| Semgrep | SAST | A02, A03 |
| OWASP Dependency-Check | SCA | A06 |
| Checkov | IaC Scan | A05 |
| OPA/Conftest | Policy-as-Code | A05 |
| Trivy | Container Scan | A06 |
| OWASP ZAP | DAST | A03, A07 |

---

## 🚀 Instrucciones para el estudiante

### Pre-requisitos
- Cuenta GitHub (gratuita)
- Suscripción Azure for Students (`az login` configurado)
- Terraform >= 1.6 instalado localmente
- Docker instalado localmente

### Paso 1 — Fork del repositorio
```bash
# 1. Hacer fork de este repo en tu cuenta de GitHub
# 2. Clonar tu fork
git clone https://github.com/TU_USUARIO/lab-devsecops-azure.git
cd lab-devsecops-azure
```

### Paso 2 — Activar el pipeline
El pipeline se ejecuta automáticamente al hacer push. Para ejecutarlo manualmente:
1. Ir a **Actions** en tu repositorio GitHub
2. Seleccionar **DevSecOps Pipeline - Azure Lab**
3. Click en **Run workflow**

### Paso 3 — Analizar hallazgos
Una vez ejecutado el pipeline:
1. Ir a **Security → Code Scanning alerts**
2. Explorar los hallazgos de Semgrep, Checkov y Trivy
3. Revisar los artefactos descargables (reporte ZAP, Dependency-Check)

### Paso 4 — Desplegar infraestructura (opcional, si el tiempo lo permite)
```bash
cd terraform/

# Inicializar Terraform
terraform init

# Ver el plan de infraestructura
terraform plan -var="container_image=python:3.12-slim"

# Aplicar (requiere suscripción Azure activa)
terraform apply

# Al finalizar el lab, destruir recursos
terraform destroy
```

### Paso 5 — Demo en clase
Preparar una presentación de 5 minutos mostrando:
1. El pipeline ejecutado (captura de pantalla de Actions)
2. Al menos **3 vulnerabilidades** detectadas con su herramienta correspondiente
3. La **remediación propuesta** para cada una
4. El **diagrama de arquitectura Azure** generado

---

## 🐛 Vulnerabilidades intencionales en `app/app.py`

La aplicación tiene vulnerabilidades **a propósito** para que las herramientas las detecten:

| # | Archivo | Línea | Vulnerabilidad | OWASP | Herramienta que la detecta |
|---|---------|-------|----------------|-------|---------------------------|
| 1 | app.py | ~14 | `SECRET_KEY` hardcodeado | A02 | Gitleaks, Semgrep |
| 2 | app.py | ~15 | `DB_PASSWORD` hardcodeado | A02 | Gitleaks, Semgrep |
| 3 | app.py | ~60 | SQL Injection en `/students/search` | A03 | Semgrep, ZAP |
| 4 | app.py | ~29 | `DEBUG=True` en producción | A05 | Semgrep, ZAP |
| 5 | app.py | ~97 | Flask en `host=0.0.0.0` sin TLS | A05 | Semgrep |

> ⚠️ **IMPORTANTE:** No corregir estas vulnerabilidades antes de ejecutar el pipeline.
> La idea es ver las herramientas detectándolas. La corrección es parte de la discusión.

---

## 📂 Estructura del repositorio

```
lab-devsecops-azure/
├── app/
│   ├── app.py              # Flask app (con vulns intencionales)
│   ├── requirements.txt    # Dependencias Python
│   └── Dockerfile          # Imagen Docker
├── terraform/
│   └── main.tf             # Infraestructura Azure completa
├── policies/
│   └── conftest/
│       └── azure_security.rego  # Políticas OPA
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml  # Pipeline completo
├── .zap/
│   └── rules.tsv           # Configuración ZAP
└── README.md
```

---

## 🔗 Referencias

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Semgrep Rules Registry](https://semgrep.dev/r)
- [Checkov Azure Checks](https://www.checkov.io/5.Policy%20Index/terraform.html)
- [OPA/Conftest Docs](https://www.conftest.dev/)
- [OWASP ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [Trivy Docs](https://aquasecurity.github.io/trivy/)
