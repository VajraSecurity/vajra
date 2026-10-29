import { Link } from 'react-router-dom';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import VisibilityIcon from '@mui/icons-material/Visibility';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import DriveFileRenameOutlineIcon from '@mui/icons-material/DriveFileRenameOutline';
import StarIcon from '@mui/icons-material/Star';
import StarBorderIcon from '@mui/icons-material/StarBorder';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../../../components/ui/dropdown-menu';
import type { Device } from '../types';

/** Per-row "…" actions menu — shared by the desktop table and mobile card layout. */
export const RowActionsMenu = ({
  device,
  triggerAriaLabel,
  triggerClassName,
  onQuickView,
  onRename,
  onToggleCritical,
}: {
  device: Device;
  triggerAriaLabel: string;
  triggerClassName?: string;
  onQuickView: (deviceId: string) => void;
  onRename: (device: Device) => void;
  onToggleCritical: (device: Device) => void;
}) => {
  const isCritical = device?.critical === true;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label={triggerAriaLabel}
        title="More actions"
        className={triggerClassName}
        onClick={(e: React.MouseEvent) => e.stopPropagation()}
      >
        <MoreVertIcon sx={{ fontSize: 18 }} />
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuItem onClick={() => onQuickView(device.id)}>
          <VisibilityIcon sx={{ fontSize: 18 }} />
          Quick view
        </DropdownMenuItem>
        <DropdownMenuItem
          render={<Link to={`/nodes/view/${encodeURIComponent(String(device?.host_identifier || ''))}`} />}
        >
          <OpenInNewIcon sx={{ fontSize: 18 }} />
          Open full profile
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => onRename(device)}>
          <DriveFileRenameOutlineIcon sx={{ fontSize: 18 }} />
          Rename
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onToggleCritical(device)}>
          {isCritical ? <StarBorderIcon sx={{ fontSize: 18 }} /> : <StarIcon sx={{ fontSize: 18 }} />}
          {isCritical ? 'Mark as non-critical' : 'Mark as critical'}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
