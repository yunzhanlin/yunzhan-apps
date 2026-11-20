export const ACTIVE_APPLICATION_COUNT = 40;
export const RETIRED_PHP_IDS = Object.freeze(["php-52", "php-53", "php-54", "php-55", "php-56", "php-70", "php-71", "php-72", "php-73", "php-74"] );
export function assertActiveApplications(apps) {
  if(!Array.isArray(apps)||apps.some(app=>RETIRED_PHP_IDS.includes(app?.id))) throw Error('PHP before 8 is retired from the application store');
}
