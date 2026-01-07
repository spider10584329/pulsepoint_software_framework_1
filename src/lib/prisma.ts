import { PrismaClient } from '@prisma/client';

const globalForPrisma = global as unknown as { prisma?: PrismaClient };

export const prisma = globalForPrisma.prisma || new PrismaClient({
  log: ['query', 'error', 'warn'],
});

// Always set the global prisma to the instance so it's reused across modules
globalForPrisma.prisma = prisma;

// Graceful shutdown helpers to avoid leaked connections in long-running processes
async function shutdownPrisma(signal?: string) {
  try {
    console.log(`Prisma: disconnecting due to ${signal || 'shutdown'}`);
    await prisma.$disconnect();
    console.log('Prisma: disconnected');
  } catch (err) {
    console.error('Prisma disconnect error:', err);
  }
}

if (typeof process !== 'undefined') {
  process.once('SIGINT', () => {
    void shutdownPrisma('SIGINT').then(() => process.exit(0));
  });

  process.once('SIGTERM', () => {
    void shutdownPrisma('SIGTERM').then(() => process.exit(0));
  });

  process.once('SIGQUIT', () => {
    void shutdownPrisma('SIGQUIT').then(() => process.exit(0));
  });

  process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    void shutdownPrisma('uncaughtException').then(() => process.exit(1));
  });

  process.on('unhandledRejection', (reason) => {
    console.error('Unhandled Rejection at:', reason);
    // don't exit immediately; log for investigation
  });
}
