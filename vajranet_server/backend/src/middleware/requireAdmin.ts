import { requireRole } from './requireRole';
import { SUPER_ADMIN_ROLE, GROUP_ADMIN_ROLE } from '../orm/entities/users/Users';

export const requireAdmin = requireRole([SUPER_ADMIN_ROLE, GROUP_ADMIN_ROLE], {
  loggerName: 'middleware.requireAdmin',
  roleLabel: 'Administrator',
  deniedMessage: 'Only Group Admins or Super Administrators can access this resource',
});
