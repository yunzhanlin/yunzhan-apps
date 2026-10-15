import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {statisticsHistoryNotice} from '../web/src/statisticsHistory.ts';
test('legacy gzip reports never claim import, while enabled pending archives remain partial',()=>{
 assert.match(statisticsHistoryNotice({history_compressed_sources:1}),/当前应用未启用压缩日志导入/);
 assert.match(statisticsHistoryNotice({history_compressed_sources:1,history_gzip_import_enabled:true}),/完整校验通过后才提交/);
 assert.match(statisticsHistoryNotice({history_compressed_sources:1,history_gzip_import_enabled:'true'}),/未启用/);
 assert.equal(statisticsHistoryNotice({history_compressed_sources:0,history_verified_compressed_sources:4,history_gzip_import_enabled:true}),undefined);
});
test('missing/conflicting/invalid inputs have precise notices without coercing unknown counters',()=>{
 const text=statisticsHistoryNotice({history_blocked_sources:2,history_missing_log:true,history_invalid_lines:1});
 for(const phrase of ['不会从头重置','没有可核对','旧压缩行','原始日志保留'])assert(text.includes(phrase));
 for(const value of [NaN,Infinity,-1,'2',false,null])assert.equal(statisticsHistoryNotice({history_compressed_sources:value}),undefined);
 assert.match(statisticsHistoryNotice({history_unsupported_rotation_sources:1}),/未静默忽略为完整历史/);
});
test('real report component uses native flags, Chinese counters and no forged enable action',()=>{
 const source=readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
 assert.match(source,/:title="statisticsHistoryNotice\(report\)"/);
 for(const phrase of ['请求标识去重已启用','识别并跳过的重复请求','旧版历史模式','完整校验过的压缩来源'])assert(source.includes(phrase));
 const helper=readFileSync(new URL('../web/src/statisticsHistory.ts',import.meta.url),'utf8');
 assert.doesNotMatch(helper,/fetch\(|localStorage|sessionStorage|Math.random/);
 const build=readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 assert(build.includes('node --test scripts/test-statistics-history.mjs'));
});

