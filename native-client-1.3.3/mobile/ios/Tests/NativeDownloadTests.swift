import XCTest
import Foundation
import CryptoKit
import Darwin
@testable import PanelAddress

private final class DownloadCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var saved: Result<NativeDownloadedFile, NativeDownloadFailure>?
    func store(_ result: Result<NativeDownloadedFile, NativeDownloadFailure>) { lock.lock();saved=result;lock.unlock() }
    var value: Result<NativeDownloadedFile, NativeDownloadFailure>? { lock.lock();defer{lock.unlock()};return saved }
}

final class NativeDownloadTests: XCTestCase {
    private var temporary: URL!
    private var directory: URL!
    private var fixture: Process!
    private var origin: String!
    private let payload = Data((0..<131137).map { UInt8(($0 * 31) & 255) })
    override func setUpWithError() throws {
        temporary=FileManager.default.temporaryDirectory.appendingPathComponent("owned-native-download-test-"+UUID().uuidString,isDirectory:true)
        try FileManager.default.createDirectory(at:temporary,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        directory=try NativeDownloadCache.prepare(temporary)
        let script=temporary.appendingPathComponent("owned-fixture.py")
        try Data(Self.server.utf8).write(to:script)
        let process=Process(),output=Pipe();process.executableURL=URL(fileURLWithPath:"/usr/bin/python3");process.arguments=["-I","-B",script.path,temporary.path];process.standardOutput=output
        let errors=temporary.appendingPathComponent("fixture.stderr");FileManager.default.createFile(atPath:errors.path,contents:nil);process.standardError=try FileHandle(forWritingTo:errors)
        try process.run();fixture=process
        var port=Data()
        while port.count<8 { guard let byte=try output.fileHandleForReading.read(upToCount:1),!byte.isEmpty else { throw NativeDownloadFailure.network };if byte==Data([10]){break};port.append(byte) }
        guard let value=String(data:port,encoding:.utf8),let number=Int(value),(1...65535).contains(number) else { throw NativeDownloadFailure.network }
        origin="http://127.0.0.1:\(number)"
    }
    override func tearDownWithError() throws {
        if fixture?.isRunning == true { fixture.terminate();fixture.waitUntilExit() }
        if let temporary { try FileManager.default.removeItem(at:temporary) }
    }
    private func transfer(_ path:String, maximum:Int64=1<<20) throws -> Result<NativeDownloadedFile,NativeDownloadFailure> {
        let done=expectation(description:"original transfer settles"),capture=DownloadCapture()
        let operation=try ForegroundFileDownload(address:PanelAddress(origin,debug:true),url:URL(string:origin+path)!,cookie:"panel_session=owned-fixture",directory:directory,maximum:maximum,reserve:0,progress:{_,_ in},completion:{result in capture.store(result);done.fulfill()})
        operation.start();wait(for:[done],timeout:15)
        return try XCTUnwrap(capture.value)
    }
    private func noPartial() throws { XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath:directory.path),[]) }
    func testActualBinaryBytesServerDigestAndOriginalFilename() throws {
        let file=try transfer("/fixed").get()
        XCTAssertEqual(try Data(contentsOf:file.url),payload);XCTAssertEqual(file.bytes,Int64(payload.count));XCTAssertEqual(file.metadata.filename,"备份+.bin");XCTAssertEqual(file.url.lastPathComponent,file.metadata.filename)
        XCTAssertEqual(file.sha256,SHA256.hash(data:payload).map{String(format:"%02x",$0)}.joined());XCTAssertEqual(file.sha256,file.metadata.serverDigest)
        var state=stat();XCTAssertEqual(lstat(file.url.path,&state),0);XCTAssertEqual(state.st_mode & 0o7777,0o600);XCTAssertEqual(state.st_nlink,1)
        file.discard();try noPartial()
    }
    func testChunkedBytesRemainBoundedAndHaveActualDigest() throws {
        let file=try transfer("/chunked").get();XCTAssertEqual(try Data(contentsOf:file.url),payload);XCTAssertNil(file.metadata.length);XCTAssertNil(file.metadata.serverDigest);XCTAssertEqual(file.bytes,Int64(payload.count));file.discard();try noPartial()
    }
    func testWrongDigestNeverBecomesAnExportableFile() throws { XCTAssertEqual(try transfer("/bad-digest").failure,.integrity);try noPartial() }
    func testAdvertisedCapacityRefusal() throws { XCTAssertEqual(try transfer("/fixed",maximum:1024).failure,.capacity);try noPartial() }
    func testUnknownSizeCannotCrossItsCapacity() throws { XCTAssertEqual(try transfer("/chunked",maximum:1024).failure,.capacity);try noPartial() }
    func testShortConnectionNeverClaimsComplete() throws { XCTAssertNotNil(try transfer("/short").failure);try noPartial() }
    func testLoginPageIsNotAnAttachment() throws { XCTAssertEqual(try transfer("/login").failure,.response);try noPartial() }
    func testAuthenticationChallengeDoesNotCreateOrReuseStoredCredentials() throws {
        XCTAssertNotNil(try transfer("/authenticate").failure)
        let records=try String(contentsOf:temporary.appendingPathComponent("requests.jsonl"),encoding:.utf8)
        let rows=try records.split(separator:"\n").map{try JSONSerialization.jsonObject(with:Data($0.utf8))as! [String:Any]}
        XCTAssertEqual(rows.count,1);XCTAssertEqual(rows.first?["path"]as?String,"/authenticate")
        XCTAssertEqual(rows.first?["authorization_present"]as?Bool,false);try noPartial()
    }
    func testRedirectDoesNotReceiveSessionOrReachTarget() throws {
        XCTAssertEqual(try transfer("/redirect").failure,.response)
        let records=try String(contentsOf:temporary.appendingPathComponent("requests.jsonl"),encoding:.utf8);XCTAssertFalse(records.contains("/target"));try noPartial()
    }
    func testCancellationSettlesOriginalTaskAndRemovesPartial() throws {
        let began=expectation(description:"real body received"),done=expectation(description:"cancel acknowledged"),capture=DownloadCapture()
        let operation=try ForegroundFileDownload(address:PanelAddress(origin,debug:true),url:URL(string:origin+"/slow")!,cookie:"panel_session=owned-fixture",directory:directory,maximum:1<<20,reserve:0,progress:{count,_ in if count>0 { began.fulfill() }},completion:{result in capture.store(result);done.fulfill()})
        operation.start();wait(for:[began],timeout:10);operation.cancel();wait(for:[done],timeout:10)
        XCTAssertEqual(capture.value?.failure,.cancelled);try noPartial()
    }
    func testCrossOriginRejectedBeforeNetwork() throws {
        XCTAssertThrowsError(try ForegroundFileDownload(address:PanelAddress(origin,debug:true),url:URL(string:origin.replacingOccurrences(of:"127.0.0.1",with:"localhost")+"/fixed")!,cookie:"owned-fixture",directory:directory,progress:{_,_ in},completion:{_ in XCTFail("must not start")}))
        try noPartial()
    }
    func testUntrustedCertificateNeverReceivesTheManagementCookie() throws {
        let certificate=temporary.appendingPathComponent("owned-server.pem"),key=temporary.appendingPathComponent("owned-server.key")
        let create=Process();create.executableURL=URL(fileURLWithPath:"/usr/bin/openssl");create.arguments=["req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost","-keyout",key.path,"-out",certificate.path]
        let log=temporary.appendingPathComponent("certificate-fixture.log");FileManager.default.createFile(atPath:log.path,contents:nil);let logHandle=try FileHandle(forWritingTo:log);create.standardOutput=logHandle;create.standardError=logHandle
        try create.run();create.waitUntilExit();try logHandle.close();XCTAssertEqual(create.terminationStatus,0)
        let old="server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True;print(server.server_port,flush=True);server.serve_forever()"
        let new="server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);import ssl;context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(sys.argv[2],sys.argv[3]);server.socket=context.wrap_socket(server.socket,server_side=True);server.daemon_threads=True;print(server.server_port,flush=True);server.serve_forever()"
        XCTAssertTrue(Self.server.contains(old));let script=temporary.appendingPathComponent("owned-TLS-fixture.py");try Data(Self.server.replacingOccurrences(of:old,with:new).utf8).write(to:script)
        let child=Process(),output=Pipe();child.executableURL=URL(fileURLWithPath:"/usr/bin/python3");child.arguments=["-I","-B",script.path,temporary.path,certificate.path,key.path];child.standardOutput=output;child.standardError=FileHandle.nullDevice;try child.run();defer{child.terminate();child.waitUntilExit()}
        var raw=Data();while raw.count<8 { let byte=try XCTUnwrap(output.fileHandleForReading.read(upToCount:1));if byte==Data([10]){break};raw.append(byte) }
        let port=try XCTUnwrap(Int(String(decoding:raw,as:UTF8.self)));let target="https://127.0.0.1:\(port)"
        let done=expectation(description:"ordinary platform TLS refusal"),capture=DownloadCapture()
        let operation=try ForegroundFileDownload(address:PanelAddress(target),url:URL(string:target+"/fixed")!,cookie:"panel_session=owned-fixture",directory:directory,maximum:1<<20,reserve:0,progress:{_,_ in},completion:{result in capture.store(result);done.fulfill()})
        operation.start();wait(for:[done],timeout:15);XCTAssertEqual(capture.value?.failure,.network);XCTAssertFalse(FileManager.default.fileExists(atPath:temporary.appendingPathComponent("requests.jsonl").path));try noPartial()
    }
    private static let server = #"""
import hashlib,http.server,json,pathlib,sys,time
root=pathlib.Path(sys.argv[1]);payload=bytes((i*31)&255 for i in range(131137))
class Handler(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def log_message(self,*args):pass
 def do_GET(self):
  cookie_ok=self.headers.get('Cookie')=='panel_session=owned-fixture'
  with(root/'requests.jsonl').open('a')as f:f.write(json.dumps({'path':self.path,'owned_fixture_cookie_only':cookie_ok,'encoding':self.headers.get('Accept-Encoding'),'authorization_present':'Authorization'in self.headers})+'\n')
  if not cookie_ok:self.send_response(401);self.send_header('Content-Length','0');self.end_headers();return
  if self.path=='/redirect':self.send_response(302);self.send_header('Location','/target');self.send_header('Content-Length','0');self.end_headers();return
  if self.path=='/authenticate':self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="owned-fixture"');self.send_header('Content-Length','0');self.end_headers();return
  if self.path=='/login':self.send_response(200);self.send_header('Content-Length','1');self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(b'x');return
  self.send_response(200);self.send_header('Content-Disposition',"attachment; filename*=UTF-8''%E5%A4%87%E4%BB%BD%2B.bin");self.send_header('Content-Type','application/octet-stream')
  if self.path in('/chunked','/slow'):self.send_header('Transfer-Encoding','chunked')
  else:self.send_header('Content-Length',str(len(payload)+(50 if self.path=='/short'else 0)))
  if self.path in('/fixed','/bad-digest'):self.send_header('X-Content-SHA256','0'*64 if self.path=='/bad-digest'else hashlib.sha256(payload).hexdigest())
  self.send_header('Connection','close');self.end_headers()
  try:
   if self.path=='/slow':self.wfile.write(b'40\r\n'+payload[:64]+b'\r\n');self.wfile.flush();time.sleep(4);self.wfile.write(b'0\r\n\r\n')
   elif self.path=='/chunked':self.wfile.write(('%x\r\n'%len(payload)).encode()+payload+b'\r\n0\r\n\r\n')
   else:self.wfile.write(payload)
   self.wfile.flush()
  except(BrokenPipeError,ConnectionResetError):pass
  self.close_connection=True
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True;print(server.server_port,flush=True);server.serve_forever()
"""#
}

private extension Result where Success == NativeDownloadedFile, Failure == NativeDownloadFailure {
    var failure:NativeDownloadFailure? { if case .failure(let error)=self{return error};return nil }
}

final class NativeDownloadMetadataTests: XCTestCase {
    private func parse(_ value:String) throws -> NativeDownloadMetadata { try NativeDownloadMetadata(disposition:value,mime:"application/octet-stream",length:nil,encoding:nil,digest:nil) }
    func testQuotedNamesUtf8AndOriginalDotFileNames() throws {
        XCTAssertEqual(try parse("attachment; filename=\"a;b.txt\"").filename,"a;b.txt")
        XCTAssertEqual(try parse("attachment; filename=fallback; filename*=UTF-8''%E5%A4%87%E4%BB%BD+.bin").filename,"备份+.bin")
        XCTAssertEqual(NativeDownloadMetadata.safeName(".env"),".env");XCTAssertEqual(NativeDownloadMetadata.safeName(".."),"yunzhan-download.bin")
    }
    func testPathAndBidiAreOnlySafeDisplayNames() throws {
        let name=try parse("attachment; filename=\"../../original.txt\"").filename
        XCTAssertFalse(name.contains("/"));XCTAssertFalse(name.contains("\\"));XCTAssertEqual(NativeDownloadMetadata.safeName("a\u{202e}b.txt"),"a_b.txt")
        let long=NativeDownloadMetadata.safeName(String(repeating:"界",count:300));XCTAssertLessThanOrEqual(long.utf8.count,180);XCTAssertFalse(long.contains("\u{fffd}"))
    }
    func testAmbiguousMetadataAndInvalidUtf8Refused() throws {
        for value in ["inline; filename=x","attachment; filename=\"unfinished","attachment; filename=a; filename=b","attachment; filename*=UTF-8''%FF.txt","attachment; filename=x\r\nInjected: x","attachment; filename=x\rInjected: x","attachment; filename=x\nInjected: x"] { XCTAssertThrowsError(try parse(value),value.debugDescription) }
        for length in ["-1","1,2","9223372036854775808","x"] { XCTAssertThrowsError(try NativeDownloadMetadata(disposition:"attachment",mime:nil,length:length,encoding:nil,digest:nil)) }
    }
    func testCookieSnapshotKeepsOnlyApplicableSameOriginCookies() throws {
        func cookie(_ name:String,_ domain:String,_ path:String,_ secure:Bool=false) -> HTTPCookie { var fields:[HTTPCookiePropertyKey:Any]=[.name:name,.value:"owned-fixture",.domain:domain,.path:path];if secure {fields[.secure]="TRUE"};return HTTPCookie(properties:fields)! }
        let cookies=[cookie("app","panel.example.test","/api"),cookie("sibling","other.example.test","/"),cookie("parent",".example.test","/"),cookie("wrongpath","panel.example.test","/other"),cookie("secure","panel.example.test","/",true)]
        let header=try NativeDownloadCookies.header(cookies,for:URL(string:"https://panel.example.test/api/file")!)
        XCTAssertTrue(header.contains("app="));XCTAssertTrue(header.contains("parent="));XCTAssertTrue(header.contains("secure="));XCTAssertFalse(header.contains("sibling="));XCTAssertFalse(header.contains("wrongpath="))
        let plain=try NativeDownloadCookies.header(cookies,for:URL(string:"http://panel.example.test/api/file")!);XCTAssertFalse(plain.contains("secure="));XCTAssertTrue(plain.contains("app="));XCTAssertTrue(plain.contains("parent="))
    }
}

final class NativeDownloadCacheTests: XCTestCase {
    private var cache:URL!
    private var root:URL!
    private var original:URL!
    override func setUpWithError() throws {
        cache=FileManager.default.temporaryDirectory.appendingPathComponent("owned-native-cache-test-"+UUID().uuidString,isDirectory:true)
        try FileManager.default.createDirectory(at:cache,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        root=cache.appendingPathComponent("native-downloads",isDirectory:true);try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        original=cache.appendingPathComponent("original-user-document");try Data([1,2,3]).write(to:original);XCTAssertEqual(chmod(original.path,0o600),0)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at:cache) }
    private func partial() -> URL { root.appendingPathComponent("download-"+UUID().uuidString.lowercased()+".part") }
    func testColdProcessOnlyRemovesItsOwnKnownTemporaryFile() throws {
        let file=partial();try Data([5]).write(to:file);XCTAssertEqual(chmod(file.path,0o600),0)
        XCTAssertEqual(try NativeDownloadCache.prepare(cache),root);XCTAssertFalse(FileManager.default.fileExists(atPath:file.path));XCTAssertEqual(try Data(contentsOf:original),Data([1,2,3]))
    }
    func testNewWindowCannotDeleteACompletedFileInThisProcess() throws {
        _ = try NativeDownloadCache.prepare(cache);let file=partial();try Data([5]).write(to:file);XCTAssertEqual(chmod(file.path,0o600),0)
        _ = try NativeDownloadCache.prepare(cache);XCTAssertEqual(try Data(contentsOf:file),Data([5]))
    }
    func testColdCleanupOfNamedExportKeepsAnOriginalDocumentOutsideItsCache() throws {
        let named=root.appendingPathComponent("download-"+UUID().uuidString.lowercased(),isDirectory:true);try FileManager.default.createDirectory(at:named,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]);let file=named.appendingPathComponent(".env");try Data([9]).write(to:file);XCTAssertEqual(chmod(file.path,0o600),0)
        _ = try NativeDownloadCache.prepare(cache);XCTAssertFalse(FileManager.default.fileExists(atPath:named.path));XCTAssertEqual(try Data(contentsOf:original),Data([1,2,3]))
    }
    func testSymbolicAndHardLinksPreserveTheirOriginalTargets() throws {
        let linked=partial();XCTAssertEqual(symlink(original.path,linked.path),0);XCTAssertThrowsError(try NativeDownloadCache.prepare(cache));XCTAssertEqual(try Data(contentsOf:original),Data([1,2,3]));XCTAssertEqual(unlink(linked.path),0)
        XCTAssertEqual(link(original.path,linked.path),0);XCTAssertThrowsError(try NativeDownloadCache.prepare(cache));var state=stat();XCTAssertEqual(lstat(original.path,&state),0);XCTAssertEqual(state.st_nlink,2);XCTAssertEqual(try Data(contentsOf:original),Data([1,2,3]))
    }
    func testWritableRootAndUnknownEvidenceAreRetained() throws {
        XCTAssertEqual(chmod(root.path,0o770),0);XCTAssertThrowsError(try NativeDownloadCache.prepare(cache));var state=stat();XCTAssertEqual(lstat(root.path,&state),0);XCTAssertEqual(state.st_mode & 0o7777,0o770)
        XCTAssertEqual(chmod(root.path,0o700),0);let unknown=root.appendingPathComponent("unknown-evidence.json");try Data([7]).write(to:unknown);XCTAssertThrowsError(try NativeDownloadCache.prepare(cache));XCTAssertEqual(try Data(contentsOf:unknown),Data([7]))
    }
}
