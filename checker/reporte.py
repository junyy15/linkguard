"""
Convierte un analisis y su veredicto en un diccionario listo para JSON.

Por que un modulo aparte y no un dataclasses.asdict() y ya:

    asdict() volcaria TODAS las tripas del programa. El dia que le cambies
    el nombre a un campo interno, rompes a todo el que ya este leyendo tu
    JSON. La salida en JSON es un CONTRATO con quien la consume.

Aqui se escribe a mano lo que se promete, y nada mas. Lo de adentro se
puede reorganizar sin romperle nada a nadie.
"""

from typing import Any

from checker.scanner import Analisis
from checker.scoring import Veredicto

# Version del formato. Si algun dia cambia la forma del JSON, esto sube,
# y quien lo consuma puede darse cuenta.
VERSION_FORMATO = 1


def _fuente_a_dict(resultado) -> dict[str, Any] | None:
    if resultado is None:
        return None
    return {
        "fuente": resultado.fuente,
        "consultado": resultado.consultado,
        "del_cache": resultado.del_cache,
        "error": resultado.error,
        "amenazas": [
            {"tipo": a.tipo, "descripcion": a.descripcion, "url": a.url}
            for a in resultado.amenazas
        ],
        "estadisticas": resultado.estadisticas or None,
    }


def a_diccionario(analisis: Analisis, veredicto: Veredicto) -> dict[str, Any]:
    """La forma publica del resultado."""
    cadena = analisis.cadena

    datos: dict[str, Any] = {
        "version": VERSION_FORMATO,
        "entrada": analisis.entrada,
        "veredicto": {
            "seguridad": veredicto.seguridad,
            "salud": veredicto.salud,
            "puntos": veredicto.puntos,
            "mensaje": veredicto.frase,
            "razones": [
                {
                    "texto": s.texto,
                    "fuente": s.fuente,
                    "peso": s.peso,
                    "decisiva": s.dura,
                }
                for s in veredicto.señales
            ],
        },
        "validacion": {
            "ok": analisis.validacion.ok,
            "url": analisis.validacion.url,
            "motivo": analisis.validacion.motivo,
            "ips": analisis.validacion.ips,
        },
        "amenazas": {
            "google_safe_browsing": _fuente_a_dict(analisis.google),
            "virustotal": _fuente_a_dict(analisis.virustotal),
        },
        "tiempo_ms": analisis.tiempo_ms,
    }

    if cadena is not None:
        datos["cadena"] = {
            "url_final": cadena.url_final,
            "redirecciones": cadena.num_saltos,
            "problema": cadena.problema,
            "cambia_de_dominio": cadena.cambia_de_dominio,
            "baja_seguridad": cadena.baja_seguridad,
            "saltos": [
                {"numero": s.numero, "url": s.url, "codigo": s.codigo,
                 "destino": s.destino}
                for s in cadena.saltos
            ],
        }
        if cadena.salud_final is not None:
            datos["salud"] = {
                "categoria": cadena.salud_final.categoria,
                "codigo": cadena.salud_final.codigo,
                "razon": cadena.salud_final.razon,
                "metodo": cadena.salud_final.metodo,
                "tiempo_ms": cadena.salud_final.tiempo_ms,
                "tipo_error": cadena.salud_final.tipo_error,
            }
    else:
        datos["cadena"] = None
        datos["salud"] = None

    return datos
