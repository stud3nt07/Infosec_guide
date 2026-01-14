# Roadmap de Seguridad de la Información

# 1. Gestión de Vulnerabilidades (Vulnerability Management)
## Preguntas Clave
A. ¿Qué tan fácilmente pueden los atacantes explotar la vulnerabilidad?
B. ¿Existen parches disponibles que solucionen la vulnerabilidad?
C. ¿Qué tipo de datos expone la vulnerabilidad?
D. ¿A cuántos sistemas afecta esta vulnerabilidad?

## 🧪 Laboratorio Práctico: Escaneo y Análisis
**Objetivo:** Identificar vulnerabilidades en un entorno controlado.
1. **Configuración:**
   - Instala una máquina virtual vulnerable (ej. [Metasploitable2](https://sourceforge.net/projects/metasploitable/)).
   - Instala una herramienta de escaneo: **Nessus Essentials** (gratuito) o **OpenVAS**.
2. **Ejercicio:**
   - Realiza un escaneo básico de red contra la IP de Metasploitable2.
   - Exporta el reporte en PDF/HTML.
   - **Tarea:** Identifica las 3 vulnerabilidades más críticas (CVSS > 9.0) y busca su CVE correspondiente.

---

# 2. Pruebas de Penetración (Penetration Testing)
## Las 4 Fases Principales
1. **Planificación:** Definir alcance (scope), objetivos, sistemas objetivo y restricciones legales.
2. **Recolección de Información (Information Gathering):** ¿Cómo recolectarás inteligencia de amenazas? (OSINT).
3. **Testeo y Explotación:** ¿Qué métodos de ataque usarás?
4. **Reporte:** ¿Cómo compartirás tus hallazgos y recomendaciones con el cliente?

### 🛠️ Herramientas Esenciales
- **Mapeo de Red:** Nmap, Masscan.
- **Escáner de Puertos:** RustScan, Nmap.
- **Escáner de Vulnerabilidades Web:** Burp Suite Community, OWASP ZAP.
- **Análisis de Paquetes:** Wireshark, TCPDump.
- **Frameworks de Explotación:** Metasploit Framework.
- **Cracking de Contraseñas:** John the Ripper, Hashcat, Hydra.

## 🧪 Laboratorio Práctico: Ataque Controlado
**Objetivo:** Explotar una vulnerabilidad conocida y documentarla.
1. **Reconocimiento:**
   - Ejecuta: `nmap -sC -sV -p- <IP_TARGET>` para listar servicios y versiones.
2. **Búsqueda de Exploits:**
   - Usa `searchsploit` o Google para buscar vulnerabilidades de las versiones encontradas (ej. vsftpd 2.3.4).
3. **Explotación:**
   - Usa **Metasploit Console** (`msfconsole`).
   - `search <nombre_servicio>`
   - `use <ruta_exploit>`
   - `set RHOSTS <IP_TARGET>`
   - `run`
   - Ejecuta el ataque para obtener una *reverse shell*.
4. **Plataformas de Práctica Recomendadas:**
   - [TryHackMe](https://tryhackme.com) (Rutas: Jr Penetration Tester).
   - [HackTheBox](https://hackthebox.com) (Máquinas: Starting Point).
   - [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) (Para pentesting web).

---

# 3. Seguridad del Sistema (System Hardening)
**Nota:** La defensa en profundidad es clave.

## Checklist de Hardening
1. **Gestión de Parches:** Automatizar actualizaciones de seguridad (`unattended-upgrades` en Linux).
2. **Minimización de Superficie:** Deshabilitar puertos y servicios innecesarios.
3. **Logging y Monitoreo:** Habilitar registros de eventos (Syslog, Windows Event Logs).
4. **Autenticación Segura:** MFA, claves SSH, políticas de contraseñas fuertes.
5. **Respaldo de Datos (Backups):** Regla 3-2-1.

## 🧪 Laboratorio Práctico: Hardening de Linux
**Objetivo:** Asegurar un servidor Linux básico.
1. **Firewall:**
   - Instala y habilita UFW (Uncomplicated Firewall).
   - Ejercicio: 
     ```bash
     sudo ufw default deny incoming
     sudo ufw default allow outgoing
     sudo ufw allow ssh
     sudo ufw enable
     ```
2. **SSH Seguro:**
   - Edita `/etc/ssh/sshd_config`.
   - Cambia el puerto por defecto (ej. 2222).
   - Deshabilita el login de root (`PermitRootLogin no`).
   - Deshabilita autenticación por contraseña (`PasswordAuthentication no`) y usa llaves SSH.
   - Reinicia el servicio: `sudo systemctl restart ssh`.
3. **Monitoreo:**
   - Instala **Fail2Ban** para banear IPs que fallen muchos intentos de login.