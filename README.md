# AI Remediation

Servicio sencillo para consultar Ollama y obtener una explicación educativa de un hallazgo de seguridad.

## Servicios

- `ollama`: ejecuta el modelo local.
- `ai-api`: expone la API protegida mediante Bearer Token.

Ollama no publica ningún puerto hacia Internet. La API se comunica con Ollama por la red interna de Docker.

## Configuración

Copia `.env.example` como `.env` y cambia `AI_API_KEY` por una clave propia.
En Dokploy, la clave debe configurarse como variable de entorno y no guardarse en Git.

## Despliegue

```bash
docker compose -f compose.yml up -d --build
docker compose -f compose.yml exec ollama ollama pull qwen2.5-coder:3b
```

La API escucha internamente en el puerto `8000`. En Dokploy se publica mediante un dominio HTTPS.

## Endpoints

```text
GET  /health
POST /api/v1/remediations
```

La consulta `POST` requiere:

```text
Authorization: Bearer tu-clave
```

El servicio no modifica repositorios, no ejecuta comandos y no decide si se permite el despliegue.
La recomendación debe ser revisada por una persona y validada mediante una nueva ejecución del analizador.

Los identificadores `CVE-TEST-*` y `TEST-*` se consideran hallazgos sintéticos y se responden sin consultar al modelo.
