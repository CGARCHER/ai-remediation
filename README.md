# AI Remediation

Servicio sencillo para consultar Ollama y obtener una explicación educativa
de un hallazgo de seguridad.

## Servicios

- `ollama`: ejecuta el modelo local.
- `ai-api`: expone la API protegida mediante una API Key.

Ollama no publica ningún puerto hacia Internet. La API se comunica con Ollama
por la red interna de Docker.

## Configuración

Copia `.env.example` como `.env` y cambia `AI_API_KEY` por una clave propia.
En Dokploy, la clave debe configurarse como variable de entorno y no guardarse
en Git.

## Despliegue

```bash
docker compose -f compose.yml up -d --build
docker compose -f compose.yml exec ollama ollama pull qwen2.5-coder:3b
```

La API escucha internamente en el puerto `8000`. En Dokploy se publicará
mediante un dominio HTTPS cuando decidamos conectarla a Internet.

## Endpoints

```text
GET  /health
POST /api/v1/remediations
```

La consulta `POST` requiere la cabecera:

```text
X-API-Key: tu-clave
```

La API solo propone una explicación y una posible remediación. No modifica
repositorios, no ejecuta comandos y no decide si se permite el despliegue.
