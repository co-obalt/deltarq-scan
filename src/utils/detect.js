import { fileExists } from './fileUtils.js';
import path from 'path';

/**
 * Auto-detect the project type based on marker files
 * @param {string} targetDir - The project root directory
 * @returns {{ type: string, label: string, markers: string[] }}
 */
export function detectProjectType(targetDir) {
  const checks = [
    {
      type: 'fastapi',
      label: 'FastAPI (Python)',
      markers: ['requirements.txt', 'pyproject.toml', 'main.py', 'app/main.py'],
      keywords: ['fastapi', 'uvicorn'],
    },
    {
      type: 'django',
      label: 'Django (Python)',
      markers: ['manage.py', 'settings.py'],
      keywords: ['django'],
    },
    {
      type: 'express',
      label: 'Express / Node.js',
      markers: ['package.json', 'server.js', 'app.js', 'index.js'],
      keywords: ['express'],
    },
    {
      type: 'nextjs',
      label: 'Next.js',
      markers: ['next.config.js', 'next.config.mjs', 'next.config.ts'],
      keywords: ['next'],
    },
    {
      type: 'golang',
      label: 'Go',
      markers: ['go.mod', 'go.sum'],
      keywords: [],
    },
    {
      type: 'ruby',
      label: 'Ruby on Rails',
      markers: ['Gemfile', 'config/routes.rb'],
      keywords: ['rails'],
    },
    {
      type: 'dotnet',
      label: '.NET',
      markers: ['*.csproj', '*.sln', 'Program.cs'],
      keywords: [],
    },
  ];

  const foundMarkers = [];

  for (const check of checks) {
    for (const marker of check.markers) {
      const fullPath = path.join(targetDir, marker);
      if (fileExists(fullPath)) {
        foundMarkers.push(marker);
        // Check for keyword matches in package.json or requirements.txt for more accuracy
        return {
          type: check.type,
          label: check.label,
          markers: [marker],
        };
      }
    }
  }

  // Check for Docker/infrastructure
  const hasDocker = fileExists(path.join(targetDir, 'Dockerfile')) ||
                    fileExists(path.join(targetDir, 'docker-compose.yml')) ||
                    fileExists(path.join(targetDir, 'docker-compose.yaml'));

  const hasPostgres = fileExists(path.join(targetDir, '.env'));

  let label = 'Unknown Project';
  const detectedParts = [];
  if (hasDocker) detectedParts.push('Docker');
  if (hasPostgres) detectedParts.push('PostgreSQL (likely)');
  if (detectedParts.length > 0) label = detectedParts.join(' + ');

  return {
    type: 'unknown',
    label,
    markers: foundMarkers,
  };
}
