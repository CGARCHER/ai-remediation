# AI Remediation

API educativa que interpreta hallazgos de seguridad y genera propuestas de remediación revisables.

## Proveedores

- `ollama`: ejecuta Qwen en el VPS.
- `gemini`: consulta la API de Gemini cuando se configura una clave.

El proveedor predeterminado se selecciona con `AI_PROVIDER`. También puede elegirse en una petición mediante `?provider=ollama` o `?provider=gemini`.

## Seguridad

La API está protegida mediante Bearer Token. No modifica repositorios, no ejecuta comandos y no aplica los parches generados. Todas las propuestas incluyen `requiresHumanReview: true`.

Ollama no publica ningún puerto hacia Internet. Las claves se configuran como variables protegidas en Dokploy y nunca se entregan al navegador.

## Configuración

Para ejecutar el proyecto en local, copia `.env.example` como `.env` y configura al menos:

```env
AI_API_KEY=una-clave-propia
AI_PROVIDER=ollama
```

Para habilitar Gemini añade:

```env
GEMINI_API_KEY=clave-generada-en-google-ai-studio
GEMINI_MODEL=gemini-flash-latest
```

No guardes el fichero `.env` en Git.

## Despliegue

```bash
docker compose -f compose.yml up -d --build
docker compose -f compose.yml exec ollama ollama pull qwen2.5-coder:3b
```

La API escucha internamente en el puerto `8000`. En Dokploy debe publicarse mediante un dominio HTTPS.

## Endpoints

```text
GET  /health
POST /api/v1/remediations
```

La consulta `POST` requiere:

```text
Authorization: Bearer tu-clave
```

Ejemplo de selección de proveedor:

```text
POST /api/v1/remediations?provider=gemini
```

## Contexto para el parche

La petición admite estos campos opcionales:

- `currentVersion`: versión utilizada.
- `fixedVersion`: versión corregida proporcionada por el analizador.
- `affectedFile`: archivo relacionado con el hallazgo.
- `line`: línea afectada.
- `sourceContext`: fragmento mínimo necesario para proponer el cambio.

La propuesta de parche solo se genera cuando `affectedFile` y `sourceContext` proporcionan información suficiente. Si faltan datos, la API devuelve `patchProposal.available: false` en lugar de inventar una solución.

Los identificadores `CVE-TEST-*` y `TEST-*` se consideran sintéticos y se responden sin consultar ningún modelo.
