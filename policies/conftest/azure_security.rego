# ============================================================
# Políticas OPA/Conftest para Terraform - Azure DevSecOps Lab
# Referencia: OWASP Top 10, CIS Azure Benchmark
# ============================================================

package main

# ─── Tags obligatorios ──────────────────────────────────────

required_tags := {"Environment", "ManagedBy"}


# ─── DENY: NSG no debe permitir acceso público al puerto 3306 (MySQL) ───
# OWASP A05 - Security Misconfiguration / CIS Azure 6.2

deny[msg] {
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

deny[msg] {
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

deny[msg] {
    resource := input.resource.azurerm_key_vault[name]

    object.get(resource, "purge_protection_enabled", false) == false

    tags := object.get(resource, "tags", {})
    lower(object.get(tags, "Environment", "")) != "lab"

    msg := sprintf(
        "Key Vault '%s': purge_protection_enabled debe ser true en entornos que no sean lab.",
        [name]
    )
}


# ─── DENY: Container Group usando imagen pública de docker.io ───────────
# Valida que imágenes de producción vengan de un registry privado

deny[msg] {
    resource := input.resource.azurerm_container_group[name]
    container := resource.container[_]

    startswith(container.image, "docker.io/")

    msg := sprintf(
        "Container Group '%s': las imágenes deben provenir de un registry privado como ACR o GHCR, no de docker.io público.",
        [name]
    )
}


# ─── WARN: MySQL sin backup_retention_days >= 7 ─────────────────────────
# ISO 27017 CLD.12.3.1

warn[msg] {
    resource := input.resource.azurerm_mysql_flexible_server[name]

    object.get(resource, "backup_retention_days", 0) < 7

    msg := sprintf(
        "MySQL Server '%s': backup_retention_days debe ser >= 7 (ISO 27017 CLD.12.3.1).",
        [name]
    )
}


# ─── WARN: Resource Group sin tags obligatorios ─────────────────────────

warn[msg] {
    resource := input.resource.azurerm_resource_group[name]

    tags := object.get(resource, "tags", {})

    present_tags := {tag |
        required_tags[tag]
        object.get(tags, tag, "") != ""
    }

    missing_tags := required_tags - present_tags

    count(missing_tags) > 0

    msg := sprintf(
        "Resource Group '%s': faltan los tags obligatorios: %v",
        [name, missing_tags]
    )
}


# ─── DENY: Variables sensibles con valor default hardcodeado ────────────

deny[msg] {
    variable := input.variable[name]

    contains(lower(name), "password")
    object.get(variable, "default", null) != null

    msg := sprintf(
        "Variable '%s': las variables de tipo password NO deben tener valor default. Use sensitive=true y páselas por variable de entorno o GitHub Secret.",
        [name]
    )
}