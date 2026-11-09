import { useEffect, useState } from 'react';
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import {
  bundledCatalog,
  nominateDefault,
  PAYPAL_EMAIL_WARNING,
  refreshCatalog,
  type CategoryCatalog,
} from '@isthisyou/dnssec-zone';
import { createDohClient, lookupDomain, lookupWallet } from '@isthisyou/dnssec-zone';

import { AppController, type DomainState, type WalletDraft } from '../app/controller';
import type { EditableUri } from '@isthisyou/dnssec-zone';
import { killSwitchCopy } from '../killswitch';

type Route =
  | { name: 'list' }
  | { name: 'add' }
  | { name: 'domain'; apex: string; tab: 'overview' | 'records' | 'registrar' | 'kill' }
  | { name: 'wallet' }
  | { name: 'info' };

export function AppShell(props: {
  controller: AppController | null;
  catalog: CategoryCatalog;
  error?: string;
  onChange: () => void;
  revision?: number;
}) {
  const [route, setRoute] = useState<Route>({ name: 'list' });
  const controller = props.controller;
  void props.revision;
  return (
    <ScrollView style={styles.page} contentContainerStyle={styles.content}>
      <Text style={styles.brand}>Is this you?</Text>
      {props.error ? <Text style={styles.warn}>{props.error}</Text> : null}
      {route.name !== 'list' ? (
        <Pressable onPress={() => setRoute({ name: 'list' })}>
          <Text style={styles.link}>All domains</Text>
        </Pressable>
      ) : null}
      {controller && route.name === 'list' ? (
        <DomainList
          controller={controller}
          onOpen={apex => setRoute({ name: 'domain', apex, tab: 'overview' })}
          onAdd={() => setRoute({ name: 'add' })}
          onWallet={() => setRoute({ name: 'wallet' })}
          onInfo={() => setRoute({ name: 'info' })}
          changed={props.onChange}
        />
      ) : null}
      {controller && route.name === 'add' ? (
        <AddDomain
          controller={controller}
          onDone={apex => {
            props.onChange();
            setRoute({ name: 'domain', apex, tab: 'overview' });
          }}
        />
      ) : null}
      {controller && route.name === 'domain' ? (
        <DomainScreen
          controller={controller}
          apex={route.apex}
          tab={route.tab}
          catalog={props.catalog}
          onTab={tab => setRoute({ name: 'domain', apex: route.apex, tab })}
          changed={props.onChange}
        />
      ) : null}
      {route.name === 'wallet' ? <WalletLookup catalog={props.catalog} controller={controller} /> : null}
      {route.name === 'info' ? <DomainInfo catalog={props.catalog} controller={controller} /> : null}
    </ScrollView>
  );
}

function DomainList(props: {
  controller: AppController;
  onOpen: (apex: string) => void;
  onAdd: () => void;
  onWallet: () => void;
  onInfo: () => void;
  changed: () => void;
}) {
  const domains = props.controller.listDomains();
  return (
    <View>
      <Text style={styles.h}>Your domains</Text>
      {domains.length === 0 ? <Text style={styles.muted}>No domains yet.</Text> : null}
      {domains.map(domain => (
        <Pressable key={domain.apex} style={styles.card} onPress={() => props.onOpen(domain.apex)}>
          <Text style={styles.cardTitle}>{domain.apex}</Text>
          <Text style={styles.muted}>
            {domain.ksk ? `KSK ${domain.ksk.hardwareTier}` : 'No keys'} ·{' '}
            {domain.lastUpload ? `serial ${domain.lastUpload.serial}` : 'not uploaded'}
            {domain.killSwitch !== 'inactive' ? ` · kill switch ${domain.killSwitch}` : ''}
          </Text>
        </Pressable>
      ))}
      <Button label="Add domain" onPress={props.onAdd} />
      <Button label="Check a wallet" onPress={props.onWallet} />
      <Button label="Look up a domain" onPress={props.onInfo} />
    </View>
  );
}

function AddDomain(props: { controller: AppController; onDone: (apex: string) => void }) {
  const defaults = props.controller.getDefaults();
  const [apex, setApex] = useState('');
  const [url, setUrl] = useState(defaults.uploadBaseUrl);
  const [ns, setNs] = useState(defaults.serviceNs.join('\n'));
  const [error, setError] = useState('');
  return (
    <View>
      <Text style={styles.h}>Add a domain</Text>
      <Field label="Domain" value={apex} onChange={setApex} />
      <Field label="Hosting upload URL" value={url} onChange={setUrl} />
      <Field label="Hosting nameservers, one per line" value={ns} onChange={setNs} multiline />
      {error ? <Text style={styles.warn}>{error}</Text> : null}
      <Button
        label="Add"
        onPress={() => {
          const names = ns.split('\n').map(item => item.trim()).filter(Boolean);
          props.controller
            .addDomain(apex, { uploadBaseUrl: url, serviceNs: names, mname: names[0] ?? defaults.mname })
            .then(() => props.onDone(apex.trim().toLowerCase().replace(/\.$/, '')))
            .catch((err: Error) => setError(err.message));
        }}
      />
    </View>
  );
}

function DomainScreen(props: {
  controller: AppController;
  apex: string;
  tab: 'overview' | 'records' | 'registrar' | 'kill';
  catalog: CategoryCatalog;
  onTab: (tab: 'overview' | 'records' | 'registrar' | 'kill') => void;
  changed: () => void;
}) {
  const domain = props.controller.getDomain(props.apex);
  return (
    <View>
      <Text style={styles.h}>{domain.apex}</Text>
      <View style={styles.row}>
        {(['overview', 'records', 'registrar', 'kill'] as const).map(tab => (
          <Pressable key={tab} onPress={() => props.onTab(tab)}>
            <Text style={props.tab === tab ? styles.tabOn : styles.tab}>{tab}</Text>
          </Pressable>
        ))}
      </View>
      {props.tab === 'overview' ? <Overview controller={props.controller} domain={domain} changed={props.changed} /> : null}
      {props.tab === 'records' ? (
        <Records controller={props.controller} domain={domain} catalog={props.catalog} changed={props.changed} />
      ) : null}
      {props.tab === 'registrar' ? <Registrar controller={props.controller} domain={domain} changed={props.changed} /> : null}
      {props.tab === 'kill' ? <Kill controller={props.controller} domain={domain} changed={props.changed} /> : null}
    </View>
  );
}

function Overview(props: { controller: AppController; domain: DomainState; changed: () => void }) {
  const [error, setError] = useState('');
  const warnings = props.controller.warnings(props.domain.apex);
  return (
    <View>
      {warnings.map(item => (
        <Text key={item.message} style={item.level === 'info' ? styles.muted : styles.warn}>
          {item.message}
        </Text>
      ))}
      {error ? <Text style={styles.warn}>{error}</Text> : null}
      <Button
        label="Generate keys"
        onPress={() =>
          props.controller.generateKeys(props.domain.apex).then(props.changed).catch((err: Error) => setError(err.message))
        }
      />
      <Button
        label="Sign and upload"
        onPress={() =>
          props.controller.signAndUpload(props.domain.apex).then(props.changed).catch((err: Error) => setError(err.message))
        }
      />
      <Button
        label="Refresh DNSKEY signature"
        onPress={() =>
          props.controller
            .signAndUpload(props.domain.apex, { resignDnskey: true })
            .then(props.changed)
            .catch((err: Error) => setError(err.message))
        }
      />
    </View>
  );
}

function Records(props: {
  controller: AppController;
  domain: DomainState;
  catalog: CategoryCatalog;
  changed: () => void;
}) {
  const [uris, setUris] = useState(props.domain.uris);
  const [wallets, setWallets] = useState(props.domain.wallets);
  const [target, setTarget] = useState('https://');
  const [category, setCategory] = useState('1');
  const [sort, setSort] = useState('1');
  const [type, setType] = useState('btc');
  const [identifier, setIdentifier] = useState('');
  const [description, setDescription] = useState('');
  const [walletSort, setWalletSort] = useState('');
  const [useEmail, setUseEmail] = useState(false);
  const [error, setError] = useState('');
  return (
    <View>
      <Text style={styles.h2}>URI records at the apex</Text>
      <Text style={styles.muted}>Priority is the category. Weight is the sort order. 0/0 is the one default URI.</Text>
      {uris.map((uri, index) => (
        <View key={`${uri.target}-${index}`} style={styles.card}>
          <Text>
            {uri.isDefault ? 'default' : props.catalog.uriCategories.find(item => item.id === uri.category)?.name ?? 'other'}{' '}
            · {uri.target}
          </Text>
          <Pressable onPress={() => setUris(nominateDefault(uris, index))}>
            <Text style={styles.link}>Make default</Text>
          </Pressable>
          <Pressable onPress={() => setUris(uris.filter((_, i) => i !== index))}>
            <Text style={styles.link}>Remove</Text>
          </Pressable>
        </View>
      ))}
      <Field label="Target" value={target} onChange={setTarget} />
      <Field label="Category number (1 or more)" value={category} onChange={setCategory} />
      <Text style={styles.muted}>
        {props.catalog.uriCategories.map(item => `${item.id} ${item.name}`).join(', ') || 'no categories loaded'}
      </Text>
      <Field label="Sort order" value={sort} onChange={setSort} />
      <Button
        label="Add URI"
        onPress={() => {
          const row: EditableUri = {
            target,
            category: Number(category),
            sort: Number(sort),
            isDefault: uris.length === 0,
          };
          setUris([...uris, row]);
        }}
      />
      <Text style={styles.h2}>WALLET records</Text>
      {wallets.map(wallet => (
        <View key={wallet.id} style={styles.card}>
          <Text>
            {wallet.type} {wallet.identifier}
            {wallet.description ? ` · ${wallet.description}` : ''}
            {wallet.sort ? ` · sort ${wallet.sort}` : ' · sort last'}
          </Text>
          <Pressable onPress={() => setWallets(wallets.filter(item => item.id !== wallet.id))}>
            <Text style={styles.link}>Remove</Text>
          </Pressable>
        </View>
      ))}
      <Field label="Type" value={type} onChange={setType} />
      <Text style={styles.muted}>
        {props.catalog.walletTypes.map(item => item.id).join(', ')} — other types are allowed
      </Text>
      <Field label="Identifier" value={identifier} onChange={setIdentifier} />
      {type.trim().toLowerCase() === 'paypal' ? (
        <View>
          <Pressable onPress={() => setUseEmail(!useEmail)}>
            <Text style={styles.link}>{useEmail ? 'Using an email address' : 'Using the 13-character account ID'}</Text>
          </Pressable>
          {useEmail ? <Text style={styles.warn}>{PAYPAL_EMAIL_WARNING}</Text> : null}
        </View>
      ) : null}
      <Field label="Description (optional)" value={description} onChange={setDescription} />
      <Field label="Sort order (optional number)" value={walletSort} onChange={setWalletSort} />
      <Button
        label="Add wallet"
        onPress={() => {
          const draft: WalletDraft = {
            id: `${Date.now()}`,
            type,
            identifier,
            description,
            sort: walletSort,
            useEmail,
          };
          setWallets([...wallets, draft]);
        }}
      />
      {error ? <Text style={styles.warn}>{error}</Text> : null}
      <Button
        label="Save records"
        onPress={() => {
          props.controller
            .saveRecords(props.domain.apex, uris, wallets)
            .then(props.changed)
            .catch((err: Error) => setError(err.message));
        }}
      />
      <Text style={styles.muted}>Saving does not publish. Sign and upload from Overview.</Text>
    </View>
  );
}

function Registrar(props: { controller: AppController; domain: DomainState; changed: () => void }) {
  const items = props.controller.checklist(props.domain.apex);
  const ds = props.controller.dsPresentation(props.domain.apex);
  const [error, setError] = useState('');
  return (
    <View>
      <Text style={styles.h2}>Registrar checklist</Text>
      {items.map(item => (
        <Text key={item.id} style={styles.body}>
          {item.done ? 'Done' : 'To do'}: {item.label}
          {item.detail ? `\n${item.detail}` : ''}
        </Text>
      ))}
      <Text style={styles.h2}>DS to publish</Text>
      <Text style={styles.mono}>{ds || 'Generate keys first.'}</Text>
      <Text style={styles.h2}>NS set</Text>
      {props.domain.settings.serviceNs.map(ns => (
        <Text key={ns} style={styles.mono}>{ns}</Text>
      ))}
      <Button
        label={props.domain.registrarDsPublished ? 'DS marked published' : 'I published the DS'}
        onPress={() => {
          props.controller.setRegistrar(props.domain.apex, { ds: !props.domain.registrarDsPublished });
          props.changed();
        }}
      />
      <Button
        label={props.domain.registrarNsPublished ? 'NS marked published' : 'I set every hosting NS'}
        onPress={() => {
          props.controller.setRegistrar(props.domain.apex, { ns: !props.domain.registrarNsPublished });
          props.changed();
        }}
      />
      {error ? <Text style={styles.warn}>{error}</Text> : null}
      <Button
        label="Upload signed zone"
        onPress={() =>
          props.controller.signAndUpload(props.domain.apex).then(props.changed).catch((err: Error) => setError(err.message))
        }
      />
    </View>
  );
}

function Kill(props: { controller: AppController; domain: DomainState; changed: () => void }) {
  const copy = killSwitchCopy(props.domain.apex, props.controller.dsPresentation(props.domain.apex) || '(no DS yet)');
  return (
    <View>
      <Text style={styles.h2}>Withdraw the DS</Text>
      <Text style={styles.body}>{copy.effect}</Text>
      {copy.steps.map(step => (
        <Text key={step} style={styles.body}>{step}</Text>
      ))}
      {copy.warnings.map(step => (
        <Text key={step} style={styles.warn}>{step}</Text>
      ))}
      <Text style={styles.muted}>Status: {props.domain.killSwitch}</Text>
      <Button
        label="Mark withdrawal pending"
        onPress={() => props.controller.setKillSwitch(props.domain.apex, 'pending').then(props.changed)}
      />
      <Button
        label="I have withdrawn the DS"
        onPress={() => props.controller.setKillSwitch(props.domain.apex, 'user_confirmed').then(props.changed)}
      />
    </View>
  );
}

function WalletLookup(props: { catalog: CategoryCatalog; controller: AppController | null }) {
  const [domain, setDomain] = useState('');
  const [type, setType] = useState('btc');
  const [identifier, setIdentifier] = useState('');
  const [result, setResult] = useState('');
  const settings = props.controller?.getDefaults();
  return (
    <View>
      <Text style={styles.h}>Does this wallet belong to this domain?</Text>
      <Field label="Domain" value={domain} onChange={setDomain} />
      <Field label="Type" value={type} onChange={setType} />
      <Field label="Identifier" value={identifier} onChange={setIdentifier} />
      <Button
        label="Check"
        onPress={() => {
          const client = createDohClient({
            baseUrl: settings?.dohUrl,
            fallbackUrl: settings?.dohFallbackUrl,
          });
          lookupWallet({ domain, type, identifier }, client, Math.floor(Date.now() / 1000))
            .then(answer => {
              const validated = answer.validated ? 'DNSSEC validated' : 'Not DNSSEC validated';
              setResult(`${answer.result.toUpperCase()} — ${validated}\n${answer.reason}`);
            })
            .catch((err: Error) => setResult(err.message));
        }}
      />
      {result ? <Text style={styles.body}>{result}</Text> : null}
      <Text style={styles.muted}>Known types: {props.catalog.walletTypes.map(item => item.name).join(', ')}</Text>
    </View>
  );
}

function DomainInfo(props: { catalog: CategoryCatalog; controller: AppController | null }) {
  const [domain, setDomain] = useState('');
  const [text, setText] = useState('');
  const settings = props.controller?.getDefaults();
  return (
    <View>
      <Text style={styles.h}>Domain info</Text>
      <Field label="Domain" value={domain} onChange={setDomain} />
      <Button
        label="Look up"
        onPress={() => {
          const client = createDohClient({
            baseUrl: settings?.dohUrl,
            fallbackUrl: settings?.dohFallbackUrl,
          });
          lookupDomain(domain, client, Math.floor(Date.now() / 1000), props.catalog)
            .then(report => {
              const lines = [
                report.dnssec.validated ? 'DNSSEC validated' : 'Not DNSSEC validated',
                report.dnssec.reason,
                report.dnssec.chain.join(' → '),
                'URIs:',
                ...report.uris.map(uri => `${uri.categoryLabel} ${uri.priority}/${uri.weight} ${uri.target}`),
                'Wallets:',
                ...report.wallets.map(wallet => `${wallet.typeLabel} ${wallet.identifier}${wallet.description ? ` (${wallet.description})` : ''}`),
              ];
              setText(lines.filter(Boolean).join('\n'));
            })
            .catch((err: Error) => setText(err.message));
        }}
      />
      {text ? <Text style={styles.body}>{text}</Text> : null}
    </View>
  );
}

function Field(props: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  multiline?: boolean;
}) {
  return (
    <View>
      <Text style={styles.label}>{props.label}</Text>
      <TextInput
        style={[styles.input, props.multiline ? styles.multi : null]}
        value={props.value}
        onChangeText={props.onChange}
        autoCapitalize="none"
        autoCorrect={false}
        multiline={props.multiline}
      />
    </View>
  );
}

function Button(props: { label: string; onPress: () => void }) {
  return (
    <Pressable style={styles.button} onPress={props.onPress}>
      <Text style={styles.buttonText}>{props.label}</Text>
    </Pressable>
  );
}

export function useAppState(): {
  controller: AppController | null;
  catalog: CategoryCatalog;
  error: string;
  revision: number;
  refresh: () => void;
} {
  const [controller, setController] = useState<AppController | null>(null);
  const [catalog, setCatalog] = useState<CategoryCatalog>(bundledCatalog());
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { createAppKeystore } = require('@isthisyou/keystore/react-native') as typeof import('@isthisyou/keystore/react-native');
        const AsyncStorage = require('@react-native-async-storage/async-storage').default as {
          getItem: (key: string) => Promise<string | null>;
          setItem: (key: string, value: string) => Promise<void>;
        };
        const store = {
          getItem: (key: string) => AsyncStorage.getItem(key),
          setItem: (key: string, value: string) => AsyncStorage.setItem(key, value),
        };
        const keystore = createAppKeystore();
        const app = new AppController(keystore, store);
        await app.load();
        const loaded = await refreshCatalog({ url: app.getDefaults().catalogUrl, store });
        if (!cancelled) {
          setCatalog(loaded.catalog);
          setController(app);
          app.resignDueDomains().then(() => setRevision(value => value + 1)).catch(() => undefined);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Could not start');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);
  return { controller, catalog, error, revision, refresh: () => setRevision(value => value + 1) };
}

const styles = StyleSheet.create({
  page: { flex: 1, backgroundColor: '#f3f0e8' },
  content: { padding: 20, paddingBottom: 48 },
  brand: { fontSize: 28, fontWeight: '700', color: '#1b1914', marginBottom: 12 },
  h: { fontSize: 20, fontWeight: '700', color: '#1b1914', marginVertical: 8 },
  h2: { fontSize: 16, fontWeight: '700', marginTop: 12, color: '#1b1914' },
  body: { color: '#1b1914', marginVertical: 4 },
  muted: { color: '#5e584e', marginVertical: 4 },
  warn: { color: '#8d1d1d', marginVertical: 4 },
  link: { color: '#0c6b58', marginVertical: 6 },
  card: { backgroundColor: '#fffdf8', borderColor: '#e2d9c8', borderWidth: 1, padding: 12, marginVertical: 6 },
  cardTitle: { fontSize: 18, color: '#1b1914' },
  label: { marginTop: 8, color: '#5e584e' },
  input: { backgroundColor: '#fff', borderColor: '#e2d9c8', borderWidth: 1, padding: 8, color: '#1b1914' },
  multi: { minHeight: 72 },
  button: { backgroundColor: '#0c6b58', padding: 12, marginTop: 10 },
  buttonText: { color: '#fffdf8', fontWeight: '700' },
  row: { flexDirection: 'row', gap: 12, marginBottom: 8 },
  tab: { color: '#5e584e', marginRight: 12 },
  tabOn: { color: '#0c6b58', fontWeight: '700', marginRight: 12 },
  mono: { fontFamily: 'monospace', color: '#1b1914' },
});
