# Repository Guidelines

## Project Structure & Module Organization

This is a TypeScript Express backend for a healthcare system. Runtime code lives in `src/`, with `src/server.ts` starting the HTTP server and `src/app.ts` configuring Express. Application code is organized under `src/app/`: shared configuration in `config/`, service clients in `lib/`, middleware in `middleware/`, helpers in `utils/`, EJS email templates in `templates/`, and features in `module/`.

Feature modules follow a file-per-layer pattern, for example `auth.controller.ts`, `auth.service.ts`, `auth.route.ts`, `auth.validation.ts`, and `auth.interface.ts`. Prisma schema files and migrations are in `prisma/schema/` and `prisma/migrations/`. Generated Prisma client code is under `src/generated/prisma/`; do not edit it manually.

## Build, Test, and Development Commands

- `npm install`: install dependencies.
- `npm run dev`: run the API locally with `tsx watch src/server.ts`.
- `npm run build`: compile TypeScript into `dist/`.
- `npm start`: run the compiled server from `dist/src/server.js`.
- `npx prisma generate`: regenerate Prisma code after schema changes.
- `npx prisma migrate dev`: create and apply local database migrations.
- `npm test`: currently a placeholder that exits with an error; add a real test script before relying on it in CI.

## Coding Style & Naming Conventions

Use TypeScript ES modules with strict type checking. Biome is configured for tabs, double quotes, organized imports, and recommended lint rules. Prefer typed interfaces and Zod validation for request payloads; avoid `any` unless the boundary requires it.

Name feature files by module and layer, such as `user.service.ts` or `auth.validation.ts`. Keep controllers thin, place business logic in services, and keep route definitions in `*.route.ts` files.

## Testing Guidelines

No test framework is configured yet. When adding tests, place them close to the module they cover or in a dedicated `tests/` directory, and use clear names such as `auth.service.test.ts`. Prioritize service logic, authentication flows, validation failures, and middleware behavior. Update `package.json` so `npm test` runs the chosen test suite.

## Commit & Pull Request Guidelines

Recent commits use short, lowercase, imperative-style summaries, for example `verify email` and `profile image upload done`. Keep commits focused on one change.

Pull requests should include a brief description, affected routes or modules, database migration notes, environment variable changes, and test/build results. Link related issues when available.

## Security & Configuration Tips

Keep secrets in `.env` and update `.env.example` when adding required variables. Review changes touching authentication, JWT handling, Cloudinary uploads, email, Redis, Bkash, Google Auth, or Prisma migrations carefully before merging.
