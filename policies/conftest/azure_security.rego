# ============================================================
# Políticas OPA/Conftest para Terraform - Azure DevSecOps Lab
# Referencia: OWASP Top 10, CIS Azure Benchmark
# ============================================================

package main

import future.keywords.if
import future.keywords.in

# ─── DENY: NSG no debe permitir acceso público al puerto 3306 (MySQL) ───
# OWASP A05 - Security Misconfiguration / CIS Azure 6.2
deny contains msg if {
    resource := input.resource.azurerm_network_security_group[name]
    rule := resource.security_rule[_]
    rule.direction == "Inbound"
    rule.access == "Allow"
    rule.destination_port_range == "3306"
    rule.source_address_prefix == "*"
    msg := sprintf(
        "NSG '%s': el puerto 3306 (MySQL) NO debe ser accesible desde Internet (source '*'). Use source_address_prefix de la subnet de la app.",
        [name]
    )
}

# ─── DENY: NSG no debe permitir acceso SSH (22) desde Internet ──────────
# CIS Azure 6.1
deny contains msg if {
    resource := input.resource.azurerm_network_security_group[name]
    rule := resource.security_rule[_]
    rule.direction == "Inbound"
    rule.access == "Allow"
    rule.destination_port_range == "22"
    rule.source_address_prefix == "*"
    msg := sprintf(
        "NSG '%s': el puerto 22 (SSH) NO debe estar abierto a Internet. Use Bastion o IP restringida.",
        [name]
    )
}

# ─── DENY: Key Vault sin purge protection en producción ─────────────────
# Nota: para labs se permite false, pero en producción debe ser true
deny contains msg if {
    resource := input.resource.azurerm_key_vault[name]
    resource.purge_protection_enabled == false
    resource.tags.Environment != "lab"
    msg := sprintf(
        "Key Vault '%s': purge_protection_enabled debe ser true en entornos que no sean lab.",
        [name]
    )
}

# ─── DENY: Container Group con ip_address_type != "Public" usando imagen sin registry ──
# Valida que imágenes de producción vengan de un registry privado (no docker.io)
deny contains msg if {
    resource := input.resource.azurerm_container_group[name]
    container := resource.container[_]
    startswith(container.image, "docker.io/")
    msg := sprintf(
        "Container '%s': las imágenes deben provenir de un registry privado (ACR/GHCR), no de docker.io público.",
        [name]
    )
}

# ─── WARN: MySQL sin backup_retention_days >= 7 ─────────────────────────
# ISO 27017 CLD.12.3.1
warn contains msg if {
    resource := input.resource.azurerm_mysql_flexible_server[name]
    resource.backup_retention_days < 7
    msg := sprintf(
        "MySQL Server '%s': backup_retention_days debe ser >= 7 (ISO 27017 CLD.12.3.1).",
        [name]
    )
}

# ─── WARN: Resource Group sin tags obligatorios ─────────────────────────
required_tags := {"Environment", "ManagedBy"}

warn contains msg if {
    resource := input.resource.azurerm_resource_group[name]
    missing := required_tags - {tag | resource.tags[tag]}
    count(missing) > 0
    msg := sprintf(
        "Resource Group '%s': faltan los tags obligatorios: %v",
        [name, missing]
    )
}

# ─── DENY: Variables sensibles con valor hardcodeado "default" sospechoso ─
deny contains msg if {
    resource := input.variable[name]
    contains(lower(name), "password")
    resource.default != null
    msg := sprintf(
        "Variable '%s': las variables de tipo password NO deben tener valor default. Use sensitive=true y páselas por env var.",
        [name]
    )
}
