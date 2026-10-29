import { requireRole } from './requireRole';
import { SUPER_ADMIN_ROLE } from '../orm/entities/users/Users';

export const requireSuperAdmin = requireRole([SUPER_ADMIN_ROLE], {
  loggerName: 'middleware.requireSuperAdmin',
  roleLabel: 'Super Administrator',
  deniedMessage: 'Only Super Administrator can access this resource',
});
