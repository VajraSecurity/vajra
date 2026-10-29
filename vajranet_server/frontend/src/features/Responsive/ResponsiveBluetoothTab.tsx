import ResponsiveHardwareBulkTab from './ResponsiveHardwareBulkTab';
import { buildBluetoothCommands } from './responsiveHardwareCommands';

const ResponsiveBluetoothTab = () => (
  <ResponsiveHardwareBulkTab
    variant="bluetooth"
    panelId="responsive-panel-bluetooth"
    ariaLabelledBy="responsive-tab-bluetooth"
    buildCommands={buildBluetoothCommands}
  />
);

export default ResponsiveBluetoothTab;
