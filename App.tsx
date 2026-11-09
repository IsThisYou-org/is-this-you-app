import { StatusBar, Text, View } from 'react-native';
import { SafeAreaProvider, useSafeAreaInsets } from 'react-native-safe-area-context';

import { AppShell, useAppState } from './src/ui/AppShell';

function Root() {
  const insets = useSafeAreaInsets();
  const state = useAppState();
  return (
    <View style={{ flex: 1, paddingTop: insets.top }}>
      <StatusBar barStyle="dark-content" />
      {state.controller || state.error ? (
        <AppShell
          controller={state.controller}
          catalog={state.catalog}
          error={state.error}
          onChange={state.refresh}
          revision={state.revision}
        />
      ) : (
        <Text style={{ padding: 20, fontSize: 28 }}>Is this you?</Text>
      )}
    </View>
  );
}

export default function App() {
  return (
    <SafeAreaProvider
      initialMetrics={{
        insets: { top: 0, right: 0, bottom: 0, left: 0 },
        frame: { x: 0, y: 0, width: 390, height: 844 },
      }}>
      <Root />
    </SafeAreaProvider>
  );
}
