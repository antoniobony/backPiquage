<?php

namespace App\Controller\api;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Psr\Container\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Filesystem\Filesystem;
use App\CSPro\UploadCasesJsonListener;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Psr\Log\LoggerInterface;
use App\Service\PdoHelper;
use App\Service\OAuthHelper;
use App\CSPro\CSProResponse;
use App\CSPro\DictionaryHelper;
use App\CSPro\DictionarySchemaHelper;
use App\CSPro\DBConfigSettings;
use App\CSPro\Data\BinaryJSONConverter;
use App\CSPro\Data\CSProResourceBuffer;
use App\CSPro\Data\CasesRepository;
use App\Security\DictionaryVoter;
use App\CSPro\Dictionary\JsonDictionaryParser;
use App\CSPro\Dictionary\Parser;
use App\Security\ApiKeyUserProvider;
use Symfony\Component\HttpKernel\Exception\HttpException;
use App\Service\AnomalyDetectionService;

class DictionaryController extends AbstractController implements ApiTokenAuthenticatedController {

    private $dictHelper;
    private $serverDeviceId;
    // Valid dictionary name pattern: alphanumeric, underscores, hyphens only
    private const DICTIONARY_NAME_PATTERN = '/^[a-zA-Z0-9_\-]+$/';


    public function __construct(private OAuthHelper $oauthService, private PdoHelper $pdo, private TokenStorageInterface $tokenStorage, private ApiKeyUserProvider $userProvider, private LoggerInterface $logger,private AnomalyDetectionService $anomalyDetectionService) {
       
    }

    //overrider the setcontainer to get access to container parameters and initiailize the dictionary helper
    public function setContainer(ContainerInterface $container = null): ?ContainerInterface {
        $dbConfigSettings = new DBConfigSettings($this->pdo, $this->logger);
        $this->serverDeviceId = $dbConfigSettings->getServerDeviceId(); //server name
        $this->dictHelper = new DictionaryHelper($this->pdo, $this->logger, $this->serverDeviceId);
        return parent::setContainer($container);
    }

    #[Route('/dictionaries/', methods: ['GET'])]
    function getDictionaryList(Request $request): CSProResponse {
        $this->logger->debug('Downloading list of dictionaries');
        $this->denyAccessUnlessGranted(DictionaryVoter::DICTIONARIES_READ);

        $stm = 'SELECT `name`, `dictionary_actual_name` AS `dictionaryName`, `dictionary_label` AS `label`, CONVERT_TZ(`modified_time`, @@session.time_zone, \'+00:00\') AS `modifiedTime` FROM `cspro_dictionaries`';
        $result = $this->pdo->fetchAll($stm);

        foreach ($result as &$row) {
            $table = $row ['name'];
            if ($this->dictHelper->tableExists($table)) {
                $stm = 'SELECT COUNT(*) AS caseCount FROM ' . $table . ' WHERE deleted = 0';
                $row ['caseCount'] = (int) $this->pdo->fetchValue($stm);
            } else {
                $row ['caseCount'] = 0;
            }

            // convert modified time to RFC3339
            $modifiedTimeUtc = \DateTime::createFromFormat('Y-m-d H:i:s', $row['modifiedTime'], new \DateTimeZone("UTC"));
            $row['modifiedTime'] = $modifiedTimeUtc->format(\DateTime::RFC3339);
        }
        unset($row);
        $response = new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR));
        $response->headers->set('Content-Length', strlen($response->getContent()));

        return $response;
    }

    #[Route('/dictionaries/', methods: ['POST'])]
    function addDictionary(Request $request): CSProResponse {
        ///add dictionary only if permitted
        $this->logger->debug('Add dictionary');
        $this->denyAccessUnlessGranted(DictionaryVoter::DICTIONARIES_WRITE);

        $dictContent = $request->getContent();
        $contentEncoding = $request->headers->get('Content-Encoding');
        if (strpos($contentEncoding, "deflate") !== false) {
            $dictContent = gzuncompress($dictContent);
        }
        $response = new CSProResponse ();

        if (JsonDictionaryParser::isValidJSON($dictContent)) {
            $parser = new JsonDictionaryParser();
        } else {
            $parser = new Parser();
        }
        try {
            $dict = $parser->parseDictionary($dictContent);
        } catch (\Exception $e) {
            $response->setError(400, 'dictionary_invalid', $e->getMessage());
            $response->setStatusCode(CSProResponse::HTTP_BAD_REQUEST);
            return $response;
        }

        $dictName = $dict->getName();

        if ($dict->hasBinaryItems()) {
            //create the folder for storing the dictionary's binary data in the files folder
            $binaryDataDirectory = $this->dictHelper->getDictionaryBinaryDataFolder($dictName, $this->getParameter('csweb_internal_files_folder'));
            if (!is_dir($binaryDataDirectory)) {
                $this->logger->info('Creating binary data directory: ' . $binaryDataDirectory);
                if (!mkdir($binaryDataDirectory, 0755, true)) {
                    $this->logger->error('Unable to create binary data directory: ' . $binaryDataDirectory);
                    $response = new CSProResponse();
                    $response->setError(403, 'dictionary_add_failed', 'Unable to create binary data directory :' . $binaryDataDirectory);
                    return $response;
                }
            }
        }
        if ($this->dictHelper->dictionaryExists($dictName)) {
            $this->dictHelper->updateExistingDictionary($dict, $dictContent, $response);
        } else {
            $this->dictHelper->createDictionary($dict, $dictContent, $response);
        }

        $response->headers->set('Content-Length', strlen($response->getContent()));
        return $response;
    }

    #[Route('/dictionaries/{dictName}/syncspec', methods: ['GET'])]
    function getDictionarySyncSpec(Request $request, $dictName): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $this->logger->debug("Download sync spec for {$dictName}");
        try {
            $this->dictHelper->checkDictionaryExists($dictName);
            $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);
            $syncURL = $this->getParameter('cspro_rest_api_url');
            $csproVersion = $this->getParameter('cspro_version');
            $csproVersion = substr($csproVersion, 0, 3); //get {Major}.{Minor} version
            $syncSpec = chr(239) . chr(187) . chr(191); //BOM
            $syncSpec .= "[Run Information]" . "\r\n";
            $syncSpec .= "Version=CSPro " . $csproVersion . "\r\n";
            $syncSpec .= "AppType=Sync" . "\r\n";
            $syncSpec .= "\r\n";
            $syncSpec .= "[ExternalFiles]" . "\r\n";
            $syncSpec .= strtoupper($dictName) . '=' . strtolower($dictName) . '.csdb' . "\r\n";
            $syncSpec .= "\r\n";
            $syncSpec .= "[Parameters]" . "\r\n";
            $syncSpec .= "SyncDirection=Get" . "\r\n";
            $syncSpec .= "SyncService=" . $syncURL . "\r\n";
            $syncSpec .= "Silent=No" . "\r\n";

            $response = new CSProResponse($syncSpec);
            $response->headers->set('Content-Length', strlen($response->getContent()));
            $response->headers->set('Content-Type', 'text/plain');
            $response->setCharset('utf-8');
            $filename = strtolower($dictName) . ".pff";
            $contentDisposition = $response->headers->makeDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, $filename);
            $response->headers->set('Content-Disposition', $contentDisposition);
        }
        catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        }
        catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'dictionary_sync_spec_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }
        return $response;
    }

    #[Route('/dictionaries/{dictName}/metadata', methods: ['GET'])]
    function getDictionaryMetaData(Request $request, $dictName): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $this->logger->debug("Download meta data for {$dictName}");

        $stm = 'SELECT id, dictionary_key_structure FROM cspro_dictionaries WHERE name = :dictName';
        $result = $this->pdo->fetchOne($stm, [ 'dictName' => $dictName ]);

        if (!$result) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        }
        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);
        $metadata = [ 'dictionaryKeyStructure' => $result['dictionary_key_structure'] ?? "" ];

        $stm = 'SELECT MAX(revision) AS maxRevision FROM cspro_sync_history WHERE dictionary_id = :dictId';
        $result = $this->pdo->fetchOne($stm, [ 'dictId' => $result['id'] ]);

        if ($result['maxRevision']) {
            $metadata = array_merge($metadata, $result);
        }

        //get user permissions for this dictionary
        $userName = $this->tokenStorage->getToken()->getUserIdentifier();
        $user = $this->userProvider->loadUserByUsername($userName);
        $roleDictPermission =  $user->getUserRole()->rolePermissions->getDictionaryPermissions($dictName);
        if(!empty($roleDictPermission)){
            $metadata['permissions'] = $roleDictPermission->getEffectivePermissions();
        }
        return CSProResponse::createJsonResponse($metadata);
    }

    #[Route('/dictionaries/{dictName}', methods: ['GET'])]
    function getDictionary(Request $request, $dictName): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $this->denyAccessUnlessGranted(DictionaryVoter::DICTIONARIES_READ);

        $stm = 'SELECT dictionary_full_content FROM cspro_dictionaries WHERE name = :dictName;';
        $bind = ['dictName' => ['dictName' => $dictName]];
        $dictText = $this->pdo->fetchValue($stm, $bind);
        $acceptEncoding = $request->headers->get('Accept-Encoding');
        $isJSONDictionary = JsonDictionaryParser::isValidJSON($dictText);
        $contentType = ($isJSONDictionary == true  || $dictText == false) ?  'application/json' : 'text/plain';
        $response = new CSProResponse();

        if ($dictText == false) {
            $response->setError(404, 'dictionary_not_found' , "Dictionary {$dictName} does not exist");
        } else {
            if(strpos($acceptEncoding, "gzip") !== false){
               //using gzencode instead of gzcompress as postman and csentry curl can uncompress this
               $dictText = gzencode($dictText);
               $response->headers->set('Content-Encoding', 'gzip');
            }
            $response->setContent($dictText);
            $response->headers->set('Content-Type', $contentType);
            $response->setCharset('utf-8');
        }
        $response->headers->set('Content-Length', strlen($response->getContent()));
        return $response;
    }

    private function processDeleteDictionary(string $dictName, bool $bDataOnly = false): CSProResponse {

        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $bind = [];
        $result = [];
        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        }
        catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        }
        catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'delete_dictionary_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }

        $this->logger->notice('Deleting dictionary: ' . $dictName);
        $strMsg = $bDataOnly ? "dictionary" : "dictionary data";
        try {
            // return the cases that are >old revision# and <> new revision#
            $this->pdo->beginTransaction();

            // Get the dictionary ID from the dictionary table;
            $stm = $stm = 'SELECT id FROM cspro_dictionaries  WHERE name = :dictName';
            $bind = [];
            $bind['dictName'] = $dictName;

            // delete data in relational database
            $dictionarySchemaHelper = new DictionarySchemaHelper($dictName, $this->pdo, $this->logger);
            $dictionarySchemaHelper->regenerateSchema();

            $this->logger->notice('Deleted data in relational (processed cases) database for dictionary: ' . $dictName);

            $dictID = $this->pdo->fetchValue($stm, $bind);

            // delete sync history
            $stm = $stm = 'DELETE FROM `cspro_sync_history` WHERE dictionary_id=:dictID';
            $bind = [];
            $bind['dictID'] = $dictID;

            $deletedSyncHistoryCount = $this->pdo->fetchAffected($stm, $bind);

            // delete dictionary from cspro_dictionaries table
            if ($bDataOnly) {// delete content when flag is set to data only
                $this->logger->notice('Deleting dictionary data for: ' . $dictName);

                //delete case binary data
                $stm = 'DELETE FROM ' . $dictName . '_case_binary_data;';
                $result = $this->pdo->query($stm);

                // delete data for dictionary TABLE
                $stm = 'DELETE FROM ' . $dictName;
                $result = $this->pdo->query($stm);
                $this->logger->notice('Deleted data for dictionary table: ' . $dictName);
            } else {// drop all the associated tables when data and dictionary are to be deleted
                $this->logger->notice('Deleting dictionary: ' . $dictName);

                $stm = 'DELETE FROM cspro_dictionaries WHERE name = :dictName';
                unset($bind);
                $bind ['dictName'] = $dictName;
                $sth = $this->pdo->prepare($stm);
                $sth->execute($bind);

                // DROP TABLE dictionary case binary data
                $stm = 'DROP TABLE IF EXISTS ' . $dictName . '_case_binary_data;';
                $result = $this->pdo->query($stm);

                // DROP TABLE dictionary;
                $stm = 'DROP TABLE IF EXISTS ' . $dictName;
                $result = $this->pdo->query($stm);

                $this->logger->notice('Dropped dictionary table: ' . $dictName);
            }

            //Some databases, including MySQL, automatically issue an implicit COMMIT when a database definition language (DDL) statement such as DROP TABLE or CREATE TABLE is issued within a transaction.
            // The implicit COMMIT will prevent you from rolling back any other changes within the transaction boundary.
            if ($this->pdo->inTransaction())
                $this->pdo->commit();

            //remove binary data directory if it exists.
            $binaryDataDirectory = $this->dictHelper->getDictionaryBinaryDataFolder($dictName, $this->getParameter('csweb_internal_files_folder'));
            $filesystem = new Filesystem();
            if ($filesystem->exists($binaryDataDirectory)) {
                try {
                    $filesystem->remove($binaryDataDirectory);
                    if ($bDataOnly) {
                        $filesystem->mkdir($binaryDataDirectory, 0755); // recreate the directory
                    }
                } catch (\Exception $e) {
                    $this->logger->error("Failed deleting binary data directory: $binaryDataDirectory " . $e->getMessage());
                }
            }
            unset($result);
            $result ['code'] = 200;
            $result ['description'] = 'Success';
            $response = new CSProResponse(json_encode($result));
            $response->headers->set('Content-Length', strlen($response->getContent()));
            $this->logger->notice("Deleted  $strMsg: $dictName");
        } catch (\Exception $e) {
            $this->logger->error("Failed deleting $strMsg $dictName", ["context" => (string) $e]);
            $this->pdo->rollBack();

            $response = new CSProResponse ();
            $response->setError(500, 'dictionary_delete_error', "Failed deleting $strMsg");
            $response->headers->set('Content-Length', strlen($response->getContent()));
        }

        return $response;
    }

    private function hasData($dictName) : bool {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            return false;
        }
        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        }
        catch (\Exception $ex) {
            return false;
        }

        $stm = 'SELECT EXISTS (SELECT 1 FROM ' . $dictName . ')';
        $result = $this->pdo->fetchValue($stm);
        $hasData = ($result === 1) ? true : false;
        return $hasData;
    }

    #[Route('/dictionaries/{dictName}/data', methods: ['DELETE'])]
    function deleteDictionaryData(Request $request, $dictName): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
         //when deleting from dashboard this custom header will be set. if it is not set only delete data if the DATA_CLEAR is set for api calls
        $fromDashBoard = $request->headers->get('x-csw-data-delete-dashboard');
        if (!isset($fromDashBoard)) {
            $this->denyAccessUnlessGranted(DictionaryVoter::DATA_CLEAR, $dictName);
        }
        $this->logger->debug("Delete data for {$dictName}");
        return $this->processDeleteDictionary($dictName, true);
    }

    #[Route('/dictionaries/{dictName}', methods: ['DELETE'])]
    function deleteDictionary(Request $request, $dictName): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $this->denyAccessUnlessGranted(DictionaryVoter::DICTIONARIES_WRITE, $dictName);
        $hasData = $this->hasData($dictName);
        //when deleting from dashboard this custom header will be set. if it is not set only delete data if the DATA_CLEAR is set for api calls
        $fromDashBoard = $request->headers->get('x-csw-data-delete-dashboard');
        if ($hasData) {
            if (!isset($fromDashBoard)){
              $this->denyAccessUnlessGranted(DictionaryVoter::DATA_CLEAR, $dictName);
            }
            $this->logger->debug("Delete dictionary and data for {$dictName}");
        }

        return $this->processDeleteDictionary($dictName, false);
    }

    // Syncs

    #[Route('/dictionaries/{dictName}/syncs', methods: ['GET'])]
    function getSyncHistory(Request $request, $dictName): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $from = $request->get('from');
        $to = $request->get('to');
        $device = $request->get('device');
        $limit = $request->get('limit');
        $offset = $request->get('offset');

        return new CSProResponse('How about implementing getSyncHistory as a GET method ?');
    }

    #[Route('/dictionaries/{dictName}/syncs', methods: ['POST'])]
    function syncCases(Request $request, $dictName): CSProResponse {
        return new CSProResponse('Method Not Allowed', CSProResponse::HTTP_METHOD_NOT_ALLOWED);
    }

    // get cases
    #[Route('/dictionaries/{dictName}/cases', methods: ['GET'])]
    function getCases(Request $request, $dictName): Response {
        $maxScriptExecutionTime = $this->getParameter('csweb_api_max_script_execution_time');
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        ini_set('max_execution_time', $maxScriptExecutionTime);
        try {
            $dictId = $this->dictHelper->checkDictionaryExists($dictName);
        }
        catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        }
        catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'get_cases_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }
        $this->logger->debug("Download cases for {$dictName}");
        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);

        $casesOptions = $request->headers->get('x-csw-cases-options');
        if (isset($casesOptions)) {
            $casesOptions = json_decode($casesOptions, true);
            if ($casesOptions !== null && json_last_error() === JSON_ERROR_NONE) {
                $casesCache = $request->headers->get('x-csw-cases-cache');
                if (isset($casesCache)) {
                    $casesCache = @gzuncompress(@base64_decode($casesCache));
                    if (!$casesCache) {
                        $this->logger->error("Error decompressing x-csw-cases-cache header");
                        return CSProResponse::createError(400, 'invalid_header', 'Error decompressing x-csw-cases-cache');
                    }

                    $casesCache = json_decode($casesCache, true);
                    if (json_last_error() != JSON_ERROR_NONE) {
                        return CSProResponse::createError(400, 'invalid_header', 'Error decoding x-csw-cases-cache as JSON');
                    }
                }

                return $this->getCasesContent($request, $dictName, $casesOptions, $casesCache);
            }
            else {
                $this->logger->error("Invalid cases options: $casesOptions" );
                $response = new CSProResponse();
                $response->setError(400, 'invalid_case_options', 'Invalid cases options query string');
                $response->headers->set('Content-Length', strlen($response->getContent()));
                return $response;
            }
        }

        //NOTE: For performance issues if a dictionary has binary data, irrespective of whether the cases have binary content, the response
        //will always be binary json format. Also, the range count in this case may not be correct as the callback will limit after a preset
        //limit for the total binary content size is reached. This should not impact the client as the client will request from the last uuid it receieved
        $isBinaryJSON = false;
        $dict = $this->dictHelper->loadDictionary($dictName);
        if ($dict->hasBinaryItems()) {
            $isBinaryJSON = true;
        }

        $response = new CSProResponse ();

        $universe = $request->headers->get('x-csw-universe');
        $universe = trim($universe, '"');
        $excludeRevisions = $request->headers->get('x-csw-exclude-revisions');

        //getCases Has eTag and deviceName
        // Check x-csw-if-revision-exists   header to see if this an update to a previous sync
        $lastRevision = null;
        $lastRevision = $request->headers->get('x-csw-if-revision-exists');
        $deviceId = $request->headers->get('x-csw-device');
        if (empty($lastRevision)) {
            $lastRevision = 0;
        }
        //get the custom headers
        $startAfterGuid = $request->headers->get('x-csw-case-range-start-after');
        $rangeCount = $request->headers->get('x-csw-case-range-count');

        if (!empty($rangeCount)) {
            $rangeCount = trim($rangeCount, ' /');
            $this->logger->debug('range count' . $rangeCount);
            if (!is_numeric($rangeCount) || $rangeCount < 0) {
                $this->logger->error('Invalid range count' . $rangeCount);
                $response->setError(400, 'invalid_range_count', 'Invalid range count header');
                $response->headers->set('Content-Length', strlen($response->getContent()));
                return $response;
            }
            $rangeCount = (int) $rangeCount;
        }

        //Get the maxFileRevision
        $maxRevision = $this->getMaxRevisionNumber();
        if (!$maxRevision)
            $maxRevision = 1;

        if ($maxRevision < $lastRevision) {
            $response->headers->set('ETag', $maxRevision);
            $response = new CSProResponse(json_encode([], JSON_FORCE_OBJECT), CSProResponse::HTTP_PRECONDITION_FAILED);
            return $response;
        }
        //Get the cases requested, if it is less than the number of cases to be sent set the response code to 206
        //otherwise set to 200
        //set the header content with #cases/#totalCases.
        #set the ETag with the new maxFileRevision
        $response = new StreamedResponse();
        //get max revision for chunk
        $bind = [];
        $bind['lastRevision'] = $lastRevision;
        $bind['maxRevision'] = $maxRevision;
        $strWhere = '';
        $universe = $request->headers->get('x-csw-universe');
        $universe = trim($universe, '"');

        $startAfterGuid = empty($startAfterGuid) ? $startAfterGuid = '' : $startAfterGuid;

        if (!empty($startAfterGuid)) {
            $strWhere = ' WHERE ((revision = :lastRevision AND  uuid > (UNHEX(REPLACE(:case_uuid' . ',"-",""))))  OR revision > :lastRevision) AND revision <= :maxRevision ';
            $bind['case_uuid'] = $startAfterGuid;
        } else {
            $strWhere = ' WHERE (revision > :lastRevision AND revision <= :maxRevision) ';
        }


        if (!empty($excludeRevisions)) {
            $arrExcludeRevisions = explode(',', $excludeRevisions);
            $strWhere .= ' AND revision NOT IN (:exclude_revisions) ';
            $bind['exclude_revisions'] = $arrExcludeRevisions;
        }
        //universe condition
        $strUniverse = '';
        if (!empty($universe)) {
            $strUniverse = ' AND (`key` LIKE :universe) ';
            $universe .= '%';
            $bind['universe'] = $universe;
        }

        $maxRevisionForChunk = $maxRevision;
        if (isset($rangeCount) && $rangeCount > 0) {
            $strChunkQuery = '( SELECT revision from ' . $dictName;
            $stm = $strChunkQuery . $strWhere . $strUniverse . ' ORDER BY revision LIMIT :rangeCount ) AS T1';
            $stm = 'SELECT max(revision) FROM ' . $stm;
            $bind['rangeCount'] = $rangeCount;
            $this->logger->debug('max revision for chunk: ' . $stm);
            $maxRevisionForChunk = $this->getMaxRevisionNumberForChunk($stm, $bind);
            unset($bind['rangeCount']);
            if ($maxRevisionForChunk <= 0)
                $maxRevisionForChunk = $maxRevision; //set it to the max revision of the full selection.
            $this->logger->debug('max revision for chunk: ' . $maxRevisionForChunk);
        }

        $caseCount = $this->getCaseCount($dictName, $universe, $excludeRevisions, $lastRevision, $maxRevision, $startAfterGuid);

        $dictController = $this;
        //archive any binary syncs sent to this device to the binary sync history archive table
        if ($isBinaryJSON) {
            $this->dictHelper->archiveBinarySyncHistoryEntries($dictId, $deviceId, $lastRevision, $startAfterGuid);
        }


        $response->setCallback(function () use ($request, $isBinaryJSON, $deviceId, $strWhere, $strUniverse, $bind, $maxRevisionForChunk, $rangeCount, $caseCount, $dictName, $dictController) {
            $casesJSONStream = fopen('php://temp', 'w+b');
            $caseBinaryItemMap = array();
            $useCompression = false;
            $acceptEncoding = $request->headers->get('Accept-Encoding');
            if (strpos($acceptEncoding, "gzip") !== false) {
                $useCompression = true;
            }
            $binaryDataDirectory = $this->dictHelper->getDictionaryBinaryDataFolder($dictName, $this->getParameter('csweb_internal_files_folder'));
            $maxPacketSize = $this->getParameter('csweb_max_sync_download_packet_size');
            $caseJSONInfo = $dictController->dictHelper->writeCasesJSONToStream($casesJSONStream, $request, $dictName, $deviceId, $binaryDataDirectory, $bind, $strWhere,
                    $strUniverse, $maxRevisionForChunk, $rangeCount, $isBinaryJSON, $caseBinaryItemMap, $maxPacketSize);
            //compression will be taken care of by apache
            if ($isBinaryJSON) {
                $outputStream = fopen('php://temp', 'w+b');
                $outputResourceBuffer = new CSProResourceBuffer($outputStream); //destructor closes the stream
                $binaryJsonConverter = new BinaryJSONConverter($this->logger);
                $binaryJsonConverter->writeBinaryJson($outputResourceBuffer, $casesJSONStream, $caseBinaryItemMap, $binaryDataDirectory);
                fclose($casesJSONStream);
                $casesJSONStream = fopen('php://temp', 'w+b');
                $outputResourceBuffer->copyToStream($casesJSONStream, null, 0);
            }
            rewind($casesJSONStream);

            //set common headers for binaryJSON and JSON format content
            $strRangeHeader = $caseJSONInfo['totalCases'] . '/' . $caseCount;
            header('x-csw-case-range-count:' . $strRangeHeader);
            header('ETag:' . $caseJSONInfo['maxRevisionForChunk']);
            header('x-csw-chunk-max-revision:' . $caseJSONInfo['maxRevisionForChunk']); //nginx  strips Etag, now using custom header
            if ($caseJSONInfo['totalCases'] < $caseCount) { //sending partial content
                header('HTTP/1.1 206 Partial Content');
            } else {//sending all the cases
                header('HTTP/1.1 200 OK');
            }
            //end common headers
            //send the content to the client in chunks if binary json if not just write out entire stream contents to the php://output stream
            $outputStream = fopen('php://output', 'wb');
            if ($isBinaryJSON) {
                $fstats = fstat($casesJSONStream);
                $length = $fstats['size'];
                //set the headers correctly for binary json
                header('Content-Type: application/octet-stream');
                if($useCompression){
                    header('Content-Encoding: deflate');
                }

                // insert a row into the sync history with the new version
                //SynchHistoryEntry out of transaction to prevent dead locks
                $userName = $dictController->tokenStorage->getToken()->getUserIdentifier();
                $lastCaseID = isset($caseJSONInfo['lastCaseId']) ? $caseJSONInfo['lastCaseId'] : "";
                $lastCaseRevision = isset($caseJSONInfo['maxRevisionForChunk']) ? $caseJSONInfo['maxRevisionForChunk'] : 0;
                $currentRevisionNumber = $this->dictHelper->addSyncHistoryEntry($deviceId, $userName, $dictName, 'get', $lastCaseRevision, $lastCaseID, $strUniverse);
                if ($isBinaryJSON && count($caseBinaryItemMap) > 0) {
                    $downloadedBinaryItemMd5s = array();
                    foreach ($caseBinaryItemMap as $binaryItems) {
                        foreach ($binaryItems as $binaryItem) {
                            $downloadedBinaryItemMd5s[] = $binaryItem['signature'];
                        }
                    }
                    $this->dictHelper->addBinarySyncHistoryEntry($dictName, $downloadedBinaryItemMd5s, $currentRevisionNumber);
                }

                $compressionFilter = null;
                if ($useCompression) {
                    // window of 31 - Filter for gzip (RFC 1952)
                    $params = array('level' => 6, 'window' => 31, 'memory' => 9);
                    $compressionFilter = stream_filter_append($outputStream, 'zlib.deflate', STREAM_FILTER_WRITE, $params);
                    header('Content-Encoding: gzip');
                }
                $chunkSize = 8 * 1024; //source code below from BinaryFileResponse::sendContent
                try {
                    while ($length && !feof($casesJSONStream)) {
                        $read = ($length > $chunkSize) ? $chunkSize : $length;
                        $read = stream_copy_to_stream($casesJSONStream, $outputStream, $read);
                        if($read === false){
                             throw new \Exception('Failed writing cases stream');
                        }
                        $length -= $read;
                        if (connection_aborted()) {
                            break;
                        }
                    }
                } finally {
                    fclose($casesJSONStream);
                }
            } else {
                header('Content-Type: application/json');
                stream_copy_to_stream($casesJSONStream, $outputStream);
                fclose($casesJSONStream);
            }
        }
        );
        return $response;
    }

    function getCasesContent($request, $dictName, $casesOptions, $casesCache): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $casesRepository = new CasesRepository($this->pdo, $this->logger, $dictName);
        $response = new CSProResponse();
        try {
            $result = $casesRepository->getCasesContent($casesOptions, $casesCache);
            $acceptEncoding = $request->headers->get('Accept-Encoding');
            $contentType = 'application/json';
            if (strpos($acceptEncoding, "gzip") !== false) {
                //using gzencode instead of gzcompress as postman and csentry curl can uncompress this
                $result = gzencode($result);
                $response->headers->set('Content-Encoding', 'gzip');
            }
            $response->setContent($result);
            $response->headers->set('Content-Type', $contentType);
            $response->setCharset('utf-8');
        } catch (\Exception $e) {
            $this->logger->error('Failed getting case from dictionary: ' . $dictName, ["context" => (string) $e]);
            $response->setError(500, 'failed_get_case', 'Failed getting case');
        }

        $response->headers->set('Content-Length', strlen($response->getContent()));
        return $response;
    }

    // Add or update cases
    #[Route('/dictionaries/{dictName}/cases', methods: ['POST'])]
    function addOrUpdateCases(Request $request, $dictName): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $result = [];
        $response = null;
        $maxScriptExecutionTime = $this->getParameter('csweb_api_max_script_execution_time');
        ini_set('max_execution_time', $maxScriptExecutionTime);

        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        }
        catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        }
        catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'get_case_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }

        $dict = $this->dictHelper->loadDictionary($dictName);

        $this->logger->debug("Add or update cases for {$dictName}");
        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_WRITE, $dictName);

        $params = [];
        $content = $request->getContent();

        $json_size = strlen($content);
        $useParser = $isBinaryJSON = false;
        $userName = $this->tokenStorage->getToken()->getUserIdentifier();
        $this->logger->debug("JSON payload size $json_size");
        if (!empty($content)) {
            $stream = $caseJSONStream = null;
            $zipFilterStream = fopen('php://temp', 'w+b');
            $contentEncoding = $request->headers->get('Content-Encoding');
            //changed to accept the correct enconding and leaving the old check for backward compatibility
            $useDecompression = strpos($contentEncoding, "gzip") !== false || strpos($contentEncoding, "deflate") !== false;
            if ($useDecompression) {
                $this->logger->debug('Using stream filter to decompress sync data');
                //deflate - Using the zlib structure (defined in RFC 1950) with the deflate compression algorithm (defined in RFC 1951).
                // Filter for deflate zlib compress (RFC 1950) - ['window' => 15] //CSPro sync sends this format
                // Filter for deflate  (RFC 1951) - ['window' => -15]
                // Filter for gzip compress (RFC 1952) - ['window' => 31]
                stream_filter_append($zipFilterStream, 'zlib.inflate', STREAM_FILTER_READ, ['window' => 15]);  // window of 15 for RFC1950 format which is what client sends
            }
            fwrite($zipFilterStream, $content);
            rewind($zipFilterStream);
            //*DO NOT CHANGE* code below - bug in php - stream with filters gets strange results when doing fseek. Copying the contents to a regular stream
            $stream = fopen('php://temp', 'w+b');
            stream_copy_to_stream($zipFilterStream, $stream);
            fclose($zipFilterStream);
            rewind($stream);
            $signature = fread($stream, strlen(BinaryJSONConverter::BINARY_CASE_HEADER));
            $isBinaryJSON = BinaryJSONConverter::IsBinaryJSON($signature);
            $content = null;
            $useParser = true;
            rewind($stream);
            $syncCasesListener = new UploadCasesJsonListener($this->pdo, $this->dictHelper, $this->logger, $request, $userName, $dictName, $isBinaryJSON);
            try {//optimize for memory usage
                $this->pdo->beginTransaction();
                $caseJSONStream = $stream;
                if ($isBinaryJSON) {
                    $caseJSONStream = fopen('php://temp', 'w+b');
                    $inputResourceBuffer = new CSProResourceBuffer($stream); //destructor closes the stream
                    $binaryJsonConverter = new BinaryJSONConverter($this->logger);
                    $binaryJsonConverter->readCasesJsonFromBinaryToStream($inputResourceBuffer, $caseJSONStream);
                    //write binary data to disk
                    $binaryDataDirectory = $this->dictHelper->getDictionaryBinaryDataFolder($dictName, $this->getParameter('csweb_internal_files_folder'));
                    $md5Signatures = $binaryJsonConverter->readBinaryCaseItemsNSave($inputResourceBuffer, $binaryDataDirectory);
                    $syncCasesListener->setUploadedBinaryCaseItems($md5Signatures);
                }
                //set case json stream parser to parse binary cases and write to DB
                $parser = new \JsonStreamingParser\Parser($caseJSONStream, $syncCasesListener);
                $syncCasesListener->setParser($parser);
                $parser->parse();
                fclose($caseJSONStream);
            } catch (\Exception $e) {
                if ($useParser)
                    fclose($caseJSONStream);
                $this->logger->error('Failed Uploading Cases to dictionary: ' . $dictName, ["context" => (string) $e]);
                if ($this->pdo->inTransaction()) {
                    $this->pdo->rollBack();
                }
                //delete the added sync history entry when rolled back
                $this->dictHelper->deleteSyncHistoryEntry($syncCasesListener->currentRevisionNumber);

                $response = new CSProResponse ();
                $response->setError(500, 'upload_cases_error', 'Failed uploading cases');
                $response->headers->set('Content-Length', strlen($response->getContent()));
                return $response;
            }
            $response = $syncCasesListener->getResponse();
            if ($response == null) {
                $response = new CSProResponse ();
                $this->logger->error('Failed Uploading Cases to dictionary: response from listener is empty');
                $response->setError(500, 'upload_cases_error', 'Failed syncing cases');
                $response->headers->set('Content-Length', strlen($response->getContent()));
            }
            return $response;
        } else {
            $response = new CSProResponse();
            $this->logger->error('Request content is Empty. Invalid sync request: ' . $dictName);
            $result ['code'] = 400;
            $result ['description'] = 'Invalid upload request';
            $response->setError($result ['code'], 'upload_cases_error', $result ['description']);
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;
        }
    }

    //route customized
    #[Route('/dictionaries/{dictName}/cases/by-page', methods: ['GET'])]
    function getCasesByPagination(Request $request, string $dictName): CSProResponse
    {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result = [
                'description' => 'Invalid dictionary name format.',
                'code'        => 400
            ];
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }

        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        } catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        } catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'get_cases_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }

        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);
        $this->logger->debug("Download cases with pagination for {$dictName}");

        // Pagination parameters
        $page  = max(1, (int) $request->query->get('page', 1));
        $limit = (int) $request->query->get('limit', 50);

        // Optional: hard limits to avoid abuse
        if ($limit < 1) {
            $limit = 50;
        }
        if ($limit > 500) {          // ajuste selon tes besoins
            $limit = 500;
        }

        $offset = ($page - 1) * $limit;

        // Optional filters (tu peux en ajouter d'autres)
        $universe = $request->query->get('universe');
        $universe = $universe ? trim($universe, '"') : null;

        try {
            $bind = [];
            $where = ' WHERE deleted = 0 ';   // on ignore les cases soft-deleted

            if (!empty($universe)) {
                $where .= ' AND (`key` LIKE :universe) ';
                $bind['universe'] = $universe . '%';
            }

            // Total count (pour la meta de pagination)
            $countStm = 'SELECT COUNT(*) FROM `' . $dictName . '`' . $where;
            $total    = (int) $this->pdo->fetchValue($countStm, $bind);

            // Cases page
            $stm = 'SELECT `id` AS position,
                        questionnaire AS `case`,
                        `revision`,
                        `uuid`
                    FROM `' . $dictName . '`'
                    . $where .
                    ' ORDER BY revision ASC, uuid ASC
                    LIMIT :limit OFFSET :offset';

            $bind['limit']  = $limit;
            $bind['offset'] = $offset;

            $rows = $this->pdo->fetchAll($stm, $bind);
            $this->dictHelper->prepareResultSetForJSON($rows);

                // Format de réponse standardisé
                $result = [
                    'data' => array_map(static function ($row) {
                        $decoded = json_decode($row['case'], true);
                        // si le JSON stocké est invalide/corrompu, on retombe sur la string brute plutôt que null
                        return (json_last_error() === JSON_ERROR_NONE) ? $decoded : $row['case'];
                    }, $rows),
                    'meta' => [
                        'page'        => $page,
                        'limit'       => $limit,
                        'total'       => $total,
                        'totalPages'  => $limit > 0 ? (int) ceil($total / $limit) : 0,
                        'hasNextPage' => ($offset + $limit) < $total,
                        'hasPrevPage' => $page > 1,
                    ]
                ];

            $response = CSProResponse::createJsonResponse($result);
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;

        } catch (\Exception $e) {
            $this->logger->error('Failed getting paginated cases from dictionary: ' . $dictName, [
                'context' => (string) $e
            ]);

            $response = new CSProResponse();
            $response->setError(500, 'failed_get_cases_paginated', 'Failed getting paginated cases');
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;
        }
    }

    #[Route('/dictionaries/{dictName}/cases/filter-infra', methods: ['GET'])]
    function getCasesByFilterInfra(Request $request, string $dictName): CSProResponse
    {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result = [
                'description' => 'Invalid dictionary name format.',
                'code'        => 400
            ];
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }

        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        } catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        } catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'get_cases_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }

        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);
        $this->logger->debug("Download cases with pagination for {$dictName}");

        // Pagination parameters
        $page  = max(1, (int) $request->query->get('page', 1));
        $limit = (int) $request->query->get('limit', 50);

        // Optional: hard limits to avoid abuse
        if ($limit < 1) {
            $limit = 50;
        }
        if ($limit > 500) {          // ajuste selon tes besoins
            $limit = 500;
        }

        $offset = ($page - 1) * $limit;

        // Optional filters (tu peux en ajouter d'autres)
        $universe = $request->query->get('universe');
        $universe = $universe ? trim($universe, '"') : null;

        // ---------------------------------------------------------------
        // Filtres spécifiques au dictionnaire "PIQUAGE_INFRASTRUCTURE_DICT".
        // IMPORTANT : `questionnaire` est stocké compressé (4 octets de préfixe
        // + zlib, voir DictHelper::prepareResultSetForJSON -> gzuncompress).
        // On NE PEUT PAS filtrer ça en SQL avec JSON_EXTRACT : il faut d'abord
        // décompresser en PHP, donc le filtrage se fait après le fetch.
        // ---------------------------------------------------------------
        $isPiquageInfra = strcasecmp($dictName, 'PIQUAGE_INFRASTRUCTURE_DICT') === 0;
        $piquageFilterParams = [
            'region', 'district', 'commune', 'agent',
            'categorie', 'type', 'proprieteBatiment', 'dateEnquete',
            'infraFonctionnelle', 'etatGeneral', 'moyenAcces', 'anneeConstruction',
        ];
        $activeFilters = [];
        if ($isPiquageInfra) {
            foreach ($piquageFilterParams as $paramName) {
                $rawValue = $request->query->get($paramName);
                if ($rawValue !== null && $rawValue !== '') {
                    $activeFilters[$paramName] = $rawValue;
                }
            }
        }

        $search = trim((string) $request->query->get('search', ''));
        $search = trim($search, '"');
        $searchTokens = [];
        if ($isPiquageInfra && $search !== '') {
            $normalized   = $this->normalizeSearchText($search);
            // "tsena ampanihy" => les deux mots doivent être présents (dans n'importe quel champ)
            $searchTokens = array_values(array_filter(preg_split('/\s+/', $normalized)));
        }

        try {
            $bind = [];
            $where = ' WHERE deleted = 0 ';   // on ignore les cases soft-deleted

            if (!empty($universe)) {
                $where .= ' AND (`key` LIKE :universe) ';
                $bind['universe'] = $universe . '%';
            }

            // =================================================================
            // CAS 1 : pas de filtre piquage_infrastructure actif
            // -> pagination SQL classique (rapide, LIMIT/OFFSET directement en base)
            // =================================================================
            if (empty($activeFilters) && empty($searchTokens)) {
                $countStm = 'SELECT COUNT(*) FROM `' . $dictName . '`' . $where;
                $total    = (int) $this->pdo->fetchValue($countStm, $bind);

                $stm = 'SELECT `id` AS position,
                            questionnaire AS `case`,
                            `revision`,
                            `uuid`
                        FROM `' . $dictName . '`'
                        . $where .
                        ' ORDER BY revision ASC, uuid ASC
                        LIMIT :limit OFFSET :offset';

                $bind['limit']  = $limit;
                $bind['offset'] = $offset;

                $rows = $this->pdo->fetchAll($stm, $bind);
                $this->dictHelper->prepareResultSetForJSON($rows);

                $data = array_map(static function ($row) {
                    $decoded = json_decode($row['case'], true);
                    return (json_last_error() === JSON_ERROR_NONE) ? $decoded : $row['case'];
                }, $rows);
            } else {
                // =================================================================
                // CAS 2 : filtre(s) piquage_infrastructure actif(s)
                // -> on récupère TOUTES les lignes correspondant au WHERE de base
                //    (sans LIMIT/OFFSET), on décompresse + décode chaque ligne,
                //    on filtre en PHP, PUIS on pagine le résultat filtré.
                //
                // Attention perf : sur une très grosse table, ça charge plus de
                // lignes que nécessaire. Si la table grossit beaucoup, la solution
                // durable est d'ajouter de vraies colonnes indexées (categorie_infra,
                // type_infra, etc.) remplies à l'écriture, pour filtrer en SQL.
                // =================================================================
                $stm = 'SELECT `id` AS position,
                            questionnaire AS `case`,
                            `revision`,
                            `uuid`
                        FROM `' . $dictName . '`'
                        . $where .
                        ' ORDER BY revision ASC, uuid ASC';

                $rows = $this->pdo->fetchAll($stm, $bind);
                $this->dictHelper->prepareResultSetForJSON($rows);

                $decodedRows = [];
                foreach ($rows as $row) {
                    $decoded = json_decode($row['case'], true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        $decodedRows[] = $decoded;
                    }
                    // si le JSON est invalide/corrompu pour cette ligne, on l'exclut
                    // silencieusement du résultat filtré (elle ne peut de toute façon
                    // pas être testée contre les filtres).
                }

                $decodedRows = array_values(array_filter(
                    $decodedRows,
                    function (array $decoded) use ($activeFilters, $searchTokens) {
                        // 1) filtres exacts par champ
                        foreach ($activeFilters as $field => $expected) {
                            $actual = $this->getPiquageInfraFieldValue($decoded, $field);
                            if ($actual === null || (string) $actual !== (string) $expected) {
                                return false;
                            }
                        }
                
                        // 2) recherche sur tous les attributs
                        if (!empty($searchTokens)) {
                            $haystack = $this->normalizeSearchText($this->flattenRecordToString($decoded));
                            foreach ($searchTokens as $token) {
                                if (!str_contains($haystack, $token)) {
                                    return false;
                                }
                            }
                        }
                
                        return true;
                    }
                ));

                $total = count($decodedRows);
                $data  = array_slice($decodedRows, $offset, $limit);
            }

            // Format de réponse standardisé
            $result = [
                'data' => $data,
                'meta' => [
                    'page'        => $page,
                    'limit'       => $limit,
                    'total'       => $total,
                    'totalPages'  => $limit > 0 ? (int) ceil($total / $limit) : 0,
                    'hasNextPage' => ($offset + $limit) < $total,
                    'hasPrevPage' => $page > 1,
                ]
            ];

            $response = CSProResponse::createJsonResponse($result);
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;

        } catch (\Exception $e) {
            $this->logger->error('Failed getting paginated cases from dictionary: ' . $dictName, [
                'context' => (string) $e
            ]);

            $response = new CSProResponse();
            $response->setError(500, 'failed_get_cases_paginated', 'Failed getting paginated cases');
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;
        }
    }

    /**
     * Extrait la valeur d'un champ du dictionnaire PIQUAGE_INFRASTRUCTURE_DICT
     * à partir des données déjà décodées (json_decode(..., true)).
     * Retourne null si le champ est absent (record répétitif vide, etc.).
     */
    private function getPiquageInfraFieldValue(array $decoded, string $field): mixed
    {
        $level = $decoded['PIQUAGE_INFRASTRUCTURE_LEVEL'] ?? null;
        if ($level === null) {
            return null;
        }

        return match ($field) {
            'region'             => $level['A1']['code'] ?? null,
            'district'           => $level['A2']['code'] ?? null,
            'commune'            => $level['A3']['code'] ?? null,
            'agent'              => $level['A']['code'] ?? null,
            'categorie'          => $level['IDENTIFICATION_REC'][0]['CATEGORIE_INFRA']['code'] ?? null,
            'type'               => $level['IDENTIFICATION_REC'][0]['TYPE_INFRA']['code'] ?? null,
            'proprieteBatiment'  => $level['IDENTIFICATION_REC'][0]['PROPRIETE_BATIMENT']['code'] ?? null,
            'dateEnquete'        => $level['IDENTIFICATION_REC'][0]['DATE_ENQUETE']['code'] ?? null,
            'infraFonctionnelle' => $level['DETAIL_REC'][0]['INFRA_FONCTIONNELLE']['code'] ?? null,
            'etatGeneral'        => $level['DETAIL_REC'][0]['ETAT_GENERAL']['code'] ?? null,
            'moyenAcces'         => $level['DETAIL_REC'][0]['MOYEN_ACCES']['code'] ?? null,
            'anneeConstruction'  => $level['DETAIL_REC'][0]['ANNEE_CONSTRUCTION']['code'] ?? null,
            'photoAile'          => $level['DETAIL_REC'][0]['PHOTO_AILE_OUI']['code'] ?? null,
            'photoFace'          => $level['DETAIL_REC'][0]['PHOTO_FACE_OUI']['code'] ?? null,
            'photoAutre'         => $level['DETAIL_REC'][0]['PHOTO_AUTRE_OUI']['code'] ?? null,
            default              => null,
        };
    }

    /**
     * Concatène toutes les valeurs scalaires d'un record (récursif),
     * y compris les records répétitifs (IDENTIFICATION_REC, DETAIL_REC...).
     * Les clés ne sont pas incluses, seulement les valeurs.
     */
    private function flattenRecordToString(mixed $data): string
    {
        if (is_array($data)) {
            $parts = [];
            foreach ($data as $value) {
                $flat = $this->flattenRecordToString($value);
                if ($flat !== '') {
                    $parts[] = $flat;
                }
            }
            return implode(' ', $parts);
        }

        if (is_string($data) || is_int($data) || is_float($data)) {
            return (string) $data;
        }

        return ''; // null, bool...
    }

    /**
     * Minuscules + suppression des accents ("Ampanihy Ouest" == "ampanihy ouest",
     * "état" == "etat").
     */
    private function normalizeSearchText(string $text): string
    {
        static $transliterator = null;
        if ($transliterator === null) {
            $transliterator = class_exists(\Transliterator::class)
                ? (\Transliterator::create('NFD; [:Nonspacing Mark:] Remove; NFC') ?: false)
                : false;
        }

        $text = mb_strtolower($text, 'UTF-8');
        return $transliterator ? $transliterator->transliterate($text) : $text;
    }

// ========================================================================
    // DASHBOARD : PIQUAGE_INFRASTRUCTURE_DICT
    // À coller dans DictionaryController, par exemple juste avant la route
    // getCase() (/cases/{caseId}). Aucun nouveau "use" n'est nécessaire.
    // ========================================================================

    /**
     * Chemins des champs dans PIQUAGE_INFRASTRUCTURE_LEVEL
     * (les mêmes que ceux de getPiquageInfraFieldValue).
     */
    private const DASH_FIELD_PATHS = [
        'region'     => ['A1'],
        'district'   => ['A2'],
        'commune'    => ['A3'],
        'agent'      => ['A'],
        'categorie'  => ['IDENTIFICATION_REC', 0, 'CATEGORIE_INFRA'],
        'type'       => ['IDENTIFICATION_REC', 0, 'TYPE_INFRA'],
        'etat'       => ['DETAIL_REC', 0, 'ETAT_GENERAL'],
        'photoFace'  => ['DETAIL_REC', 0, 'PHOTO_FACE_OUI'],
        'photoAile'  => ['DETAIL_REC', 0, 'PHOTO_AILE_OUI'],
        'photoAutre' => ['DETAIL_REC', 0, 'PHOTO_AUTRE_OUI'],
    ];

    /**
     * Libellés de secours pour ETAT_GENERAL si le JSON ne contient pas de "label".
     * À VÉRIFIER : suppose 1 = Neuf, 2 = Bon état, 3 = Moyen état, 4 = Mauvais état.
     */
    private const DASH_ETAT_LABELS = [
        '1' => 'Neuf',
        '2' => 'Bon état',
        '3' => 'Moyen état',
        '4' => 'Mauvais état',
    ];

    /** Renvoie le noeud d'un champ (ex. ['code' => '801', ...]) ou null s'il est absent. */
    private function dashNode(array $decoded, string $key): mixed
    {
        $node = $decoded['PIQUAGE_INFRASTRUCTURE_LEVEL'] ?? null;
        foreach (self::DASH_FIELD_PATHS[$key] as $step) {
            if (!is_array($node) || !array_key_exists($step, $node)) {
                return null;
            }
            $node = $node[$step];
        }
        return $node;
    }

    /** Code d'un noeud sous forme de chaîne, ou null s'il est vide. */
    private function dashCode(mixed $node): ?string
    {
        $value = is_array($node) ? ($node['code'] ?? null) : $node;
        if ($value === null || $value === '' || is_array($value) || is_bool($value)) {
            return null;
        }
        return (string) $value;
    }

    /** Libellé d'un noeud, s'il existe dans le JSON. */
    private function dashLabel(mixed $node): ?string
    {
        if (!is_array($node)) {
            return null;
        }
        $label = $node['label'] ?? null;
        return (is_string($label) && $label !== '') ? $label : null;
    }

    /** Incrémente le compteur d'un code et mémorise son libellé. */
    private function dashTally(array &$counts, array &$labels, ?string $code, ?string $label): void
    {
        if ($code === null) {
            return;
        }
        $counts[$code] = ($counts[$code] ?? 0) + 1;
        if ($label !== null && !isset($labels[$code])) {
            $labels[$code] = $label;
        }
    }

    /** Transforme [code => nombre] en liste triée par nombre décroissant. */
    private function dashRanked(array $counts, array $labels): array
    {
        arsort($counts);
        $out = [];
        foreach ($counts as $code => $value) {
            $out[] = ['code' => (string) $code, 'label' => $labels[$code] ?? null, 'value' => $value];
        }
        return $out;
    }

    /**
     * Paramètre Symfony du dossier racine des fichiers de l'API
     * (le même que dans FoldersController : /api/folders/...).
     */
    private const DASH_FILES_PARAM = 'csweb_api_files_folder';

    /** Sous-dossier des photos, relatif à la racine : /photos/PIQUAGE_INFRA/ */
    private const DASH_PHOTOS_SUBDIR = 'photos' . DIRECTORY_SEPARATOR . 'PIQUAGE_INFRA';

    /**
     * Compte les photos présentes dans le dossier des photos.
     * Lecture directe du dossier, sans passer par CSProFileManager : on évite ainsi
     * le calcul du MD5 de chaque fichier que fait /api/folders/... par défaut.
     *   INFRA_Face_*.jpg  => face
     *   INFRA_Aile_*.jpg  => aile
     *   Autre_*.jpg       => autre (une infrastructure peut en avoir plusieurs)
     *
     * Renvoie null si le dossier est introuvable : l'appelant retombe alors
     * sur le comptage à partir des fiches.
     */
    private function dashCountPhotoFiles(): ?array
    {
        try {
            $root = rtrim((string) $this->getParameter(self::DASH_FILES_PARAM), '/\\');
        } catch (\Throwable $e) {
            $this->logger->warning('Dashboard: paramètre ' . self::DASH_FILES_PARAM . ' introuvable : ' . $e->getMessage());
            return null;
        }

        $dir = $root . DIRECTORY_SEPARATOR . self::DASH_PHOTOS_SUBDIR;
        if (!is_dir($dir)) {
            $this->logger->warning('Dashboard: dossier de photos introuvable : ' . $dir);
            return null;
        }

        $counts = ['face' => 0, 'aile' => 0, 'autre' => 0];
        foreach (new \DirectoryIterator($dir) as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $name = $file->getFilename();
            if (!preg_match('/\.(jpe?g|png|webp)$/i', $name)) {
                continue;
            }
            if (stripos($name, 'INFRA_Face_') === 0) {
                $counts['face']++;
            } elseif (stripos($name, 'INFRA_Aile_') === 0) {
                $counts['aile']++;
            } elseif (stripos($name, 'Autre_') === 0) {
                $counts['autre']++;
            }
        }
        return $counts;
    }

    /**
     * Toutes les statistiques du tableau de bord en un seul appel.
     *
     * GET /dictionaries/PIQUAGE_INFRASTRUCTURE_DICT/cases/dashboard-infra
     *
     * Filtres facultatifs (égalité exacte sur le code) :
     *   ?region=&district=&commune=&agent=&categorie=&type=
     * Option : ?topAgents=5 (1 à 50)
     */
    #[Route('/dictionaries/{dictName}/cases/dashboard-infra', methods: ['GET'])]
    function getDashboardInfra(Request $request, string $dictName): CSProResponse
    {
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result = ['description' => 'Invalid dictionary name format.', 'code' => 400];
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        if (strcasecmp($dictName, 'PIQUAGE_INFRASTRUCTURE_DICT') !== 0) {
            return CSProResponse::createError(
                400,
                'unsupported_dictionary',
                'Dashboard is only available for PIQUAGE_INFRASTRUCTURE_DICT'
            );
        }

        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        } catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        } catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'get_cases_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }

        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);
        $this->logger->debug("Dashboard statistics for {$dictName}");
        ini_set('max_execution_time', $this->getParameter('csweb_api_max_script_execution_time'));

        // Filtres facultatifs
        $filters = [];
        foreach (['region', 'district', 'commune', 'agent', 'categorie', 'type'] as $param) {
            $value = $request->query->get($param);
            if ($value !== null && $value !== '') {
                $filters[$param] = (string) $value;
            }
        }
        $topAgents = min(50, max(1, (int) $request->query->get('topAgents', 5)));

        // Compteurs
        $total = $withPhotos = $faceCount = $aileCount = $autreCount = 0;
        $statusCounts = $statusLabels = [];
        $categoryCounts = $categoryLabels = [];
        $typeCounts = $typeLabels = [];
        $agentCounts = $agentLabels = [];
        $regionCounts = $regionLabels = [];

        try {
            // Lecture par paquets de 500 lignes : `questionnaire` est compressé,
            // on le décompresse paquet par paquet pour limiter la mémoire.
            $chunkSize = 500;
            $lastId = 0;
            $stm = 'SELECT `id` AS position, questionnaire AS `case`, `revision`, `uuid`
                    FROM `' . $dictName . '`
                    WHERE deleted = 0 AND `id` > :lastId
                    ORDER BY `id` ASC
                    LIMIT :limit';

            do {
                $rows = $this->pdo->fetchAll($stm, ['lastId' => $lastId, 'limit' => $chunkSize]);
                if (empty($rows)) {
                    break;
                }
                $rowCount = count($rows);
                $lastId = (int) $rows[$rowCount - 1]['position']; // avant la transformation
                $this->dictHelper->prepareResultSetForJSON($rows);

                foreach ($rows as $row) {
                    $decoded = json_decode($row['case'], true);
                    if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
                        continue; // ligne corrompue : ignorée
                    }

                    // Filtres
                    foreach ($filters as $field => $expected) {
                        if ($this->dashCode($this->dashNode($decoded, $field)) !== $expected) {
                            continue 2;
                        }
                    }

                    $total++;

                    // Photos : présentes si le champ contient une valeur
                    $hasFace  = $this->dashCode($this->dashNode($decoded, 'photoFace')) !== null;
                    $hasAile  = $this->dashCode($this->dashNode($decoded, 'photoAile')) !== null;
                    $hasAutre = $this->dashCode($this->dashNode($decoded, 'photoAutre')) !== null;
                    if ($hasFace)  { $faceCount++; }
                    if ($hasAile)  { $aileCount++; }
                    if ($hasAutre) { $autreCount++; }
                    if ($hasFace || $hasAile || $hasAutre) { $withPhotos++; }

                    // Répartitions
                    $node = $this->dashNode($decoded, 'etat');
                    $this->dashTally($statusCounts, $statusLabels, $this->dashCode($node), $this->dashLabel($node));
                    $node = $this->dashNode($decoded, 'categorie');
                    $this->dashTally($categoryCounts, $categoryLabels, $this->dashCode($node), $this->dashLabel($node));
                    $node = $this->dashNode($decoded, 'type');
                    $this->dashTally($typeCounts, $typeLabels, $this->dashCode($node), $this->dashLabel($node));
                    $node = $this->dashNode($decoded, 'agent');
                    $this->dashTally($agentCounts, $agentLabels, $this->dashCode($node), $this->dashLabel($node));
                    $node = $this->dashNode($decoded, 'region');
                    $this->dashTally($regionCounts, $regionLabels, $this->dashCode($node), $this->dashLabel($node));
                }
                unset($rows);
            } while ($rowCount === $chunkSize);

            // États, dans l'ordre des codes, avec libellé de secours
            ksort($statusCounts);
            $status = [];
            foreach ($statusCounts as $code => $value) {
                $code = (string) $code;
                $status[] = [
                    'code'  => $code,
                    'label' => $statusLabels[$code] ?? self::DASH_ETAT_LABELS[$code] ?? null,
                    'value' => $value,
                ];
            }

            ksort($typeCounts);

            // Photos : comptées dans le dossier quand aucun filtre n'est actif
            // (les fichiers ne peuvent pas être filtrés par région/agent de façon fiable).
            // Sinon, ou si le dossier est illisible, on garde le comptage des fiches.
            $photoSource = 'json';
            if (empty($filters)) {
                $files = $this->dashCountPhotoFiles();
                if ($files !== null) {
                    $faceCount  = $files['face'];
                    $aileCount  = $files['aile'];
                    $autreCount = $files['autre'];
                    $photoSource = 'files';
                }
            }

            $agents = array_map(
                static fn(array $a) => ['id' => $a['code'], 'value' => $a['value']],
                array_slice($this->dashRanked($agentCounts, $agentLabels), 0, $topAgents)
            );

            $result = [
                'total'         => $total,
                'withPhotos'    => $withPhotos,
                'withoutPhotos' => $total - $withPhotos,
                'faceCount'     => $faceCount,
                'aileCount'     => $aileCount,
                'autreCount'    => $autreCount,
                'photoSource'   => $photoSource, // 'files' (dossier) ou 'json' (fiches)
                'status'        => $status,
                'categories'    => $this->dashRanked($categoryCounts, $categoryLabels),
                'typeCounts'    => (object) $typeCounts, // {"801": 201, ...} même si vide
                'agents'        => $agents,
                'regions'       => $this->dashRanked($regionCounts, $regionLabels),
                'generatedAt'   => gmdate(\DATE_ATOM),
            ];

            $response = CSProResponse::createJsonResponse($result);
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;
        } catch (\Exception $e) {
            $this->logger->error('Failed building dashboard for dictionary: ' . $dictName, [
                'context' => (string) $e
            ]);
            $response = new CSProResponse();
            $response->setError(500, 'failed_dashboard_infra', 'Failed building dashboard');
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;
        }
    }

    /**
     * Nombre de fiches (non supprimées) d'un dictionnaire.
     * Utile pour le badge « fiches sociales » (dictionnaire de sécurité sociale).
     *
     * GET /dictionaries/{dictName}/cases/count
     */
    #[Route('/dictionaries/{dictName}/cases/count', methods: ['GET'])]
    function getCasesCount(Request $request, string $dictName): CSProResponse
    {
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result = ['description' => 'Invalid dictionary name format.', 'code' => 400];
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }

        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        } catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        } catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'get_cases_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }

        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);

        try {
            $total = (int) $this->pdo->fetchValue('SELECT COUNT(*) FROM `' . $dictName . '` WHERE deleted = 0');
            $response = CSProResponse::createJsonResponse(['dictionary' => $dictName, 'total' => $total]);
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;
        } catch (\Exception $e) {
            $this->logger->error('Failed counting cases for dictionary: ' . $dictName, ['context' => (string) $e]);
            $response = new CSProResponse();
            $response->setError(500, 'failed_count_cases', 'Failed counting cases');
            $response->headers->set('Content-Length', strlen($response->getContent()));
            return $response;
        }
    }


    // Get a case. To get case by case ids and more options use /cases/ endpoint
    #[Route('/dictionaries/{dictName}/cases/{caseId}', methods: ['GET'],requirements: ['caseId' => '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'])]
    function getCase(Request $request, $dictName, $caseId): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        }
        catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found', "Dictionary {$dictName} does not exist");
            return $response;
        }
        catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'get_case_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }
        $this->logger->debug("Download case by id {$caseId} for {$dictName}");
        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);
        return $this->getCaseByGUID($dictName, $caseId);
    }

    // Gets the binary data associated with a case.
    #[Route('/dictionaries/{dictName}/binary-data/{signature}', methods: ['GET'])]
    function getBinaryData(Request $request, $dictName, $signature): Response {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        try {
            $this->dictHelper->checkDictionaryExists($dictName);
        }
        catch (HttpException $ex) {
            $response = new CSProResponse();
            $response->setError(404, 'dictionary_not_found' ,  "Dictionary {$dictName} does not exist");
            return $response;
        }
        catch (\Exception $ex) {
            $response = new CSProResponse();
            $response->setError(500, 'binary_data_get_error', "An unexpected error occurred: " . $ex->getMessage());
            return $response;
        }
        $this->logger->debug("Download binary data associated with case {$signature} for {$dictName}");
        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_READ, $dictName);

        $binaryDataDirectory = $this->dictHelper->getDictionaryBinaryDataFolder($dictName, $this->getParameter('csweb_internal_files_folder'));
        $filePath = $binaryDataDirectory . DIRECTORY_SEPARATOR . $signature;

        try {
            $response = new BinaryFileResponse($filePath);
            $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, $signature);
            $response->headers->set('Content-MD5', $signature);
            return $response;
        }
        catch (\Exception $e) {
            return CSProResponse::createError(404, 'file_not_found', 'File not found');
        }
    }

    function getCaseByGUID($dictName, $caseId): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        $response = new CSProResponse ();
        try {
            // the statement to prepare
            $stm = "SELECT `id` AS position, questionnaire AS `case`, `revision`
                FROM " . $dictName . ' WHERE uuid =(UNHEX(REPLACE(:case_uuid' . ',"-","")))';

            $bind = [];
            $bind['case_uuid'] = $caseId;

            $result = $this->pdo->fetchAll($stm, $bind);
            $this->dictHelper->prepareResultSetForJSON($result);
            if (!$result) {
                $response = new CSProResponse ();
                $response->setError(404, 'case_not_found', 'Case not found');
            } else {
                $resultCase = $result [0];
                $response = new CSProResponse($resultCase['case']);
            }
        } catch (\Exception $e) {
            $this->logger->error('Failed getting case from dictionary: ' . $dictName, ["context" => (string) $e]);
            $response->setError(500, 'failed_get_case', 'Failed getting case');
        }

        $response->headers->set('Content-Length', strlen($response->getContent()));
        return $response;
    }

    // Update a case. Body is required to be a json array with single element
    #[Route('/dictionaries/{dictName}/cases/{caseId}', methods: ['PUT'])]
    function updateCase(Request $request, $dictName, $caseId): CSProResponse {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            $result['description'] = 'Invalid dictionary name format.';
            $result['code'] = 400;
            return new CSProResponse(json_encode($result, JSON_THROW_ON_ERROR), Response::HTTP_BAD_REQUEST);
        }
        if (!$this->dictHelper->checkCaseExists($dictName, $caseId)) {
            $response = new CSProResponse ();
            $response->setError(404, 'case_not_found', 'Case not found');
            return $response;
        }

        $this->logger->debug("Update case by id {$caseId} for {$dictName}");
        $this->denyAccessUnlessGranted(DictionaryVoter::DATA_WRITE, $dictName);

        //NOTE: if multiple cases are sent this will add or update those cases in the case json array.
        return $this->addOrUpdateCases($request, $dictName);
    }

    #[Route('/dictionaries/{dictName}/cases/{caseId}', methods: ['DELETE'])]
    function deleteCase(Request $request, $dictName, $caseId): CSProResponse {
        //'This HTTP method is not supported for this endpoint. Deletion is allowed only through Sync.'
        $response = new CSProResponse ();
        $response->setError(CSProResponse::HTTP_METHOD_NOT_ALLOWED, 'method_not_allowed', 'Deletion is allowed only through Sync.');
        return $response;
    }

    function getMaxRevisionNumber() {
        try {
            //returns the max revision in the cspro_sync_history table
            //may not match the max revision of the dictionary cases table
            $stm = 'SELECT max(revision)  FROM  cspro_sync_history';
            $maxRevison = (int) $this->pdo->fetchValue($stm);
            return $maxRevison;
        } catch (\Exception $e) {
            throw new \Exception('Failed in getMaxRevisionNumber ', 0, $e);
        }
    }

    function getMaxRevisionNumberForChunk($stm, $bind) {
        try {
            $maxRevison = (int) $this->pdo->fetchValue($stm, $bind);
            return $maxRevison;
        } catch (\Exception $e) {
            throw new \Exception('Failed in getMaxRevisionNumberForChunk ', 0, $e);
        }
    }

    function getCaseCount($dictName, $universe, $excludeRevisions, $lastRevision, $maxRevision, $startAfterGuid) {
        // Validate dictionary name format before using it
        if (empty($dictName) || !preg_match(self::DICTIONARY_NAME_PATTERN, $dictName)) {
            throw new \Exception("Invalid dictionary name format $dictName");
        }
        try {
            if (empty($maxRevision)) {
                throw new \Exception('Failed in getCaseCount ' . $dictName . 'Expecting maxRevision to be set.');
            }
            $bind = [];

            $lastRevision = empty($lastRevision) ? 0 : $lastRevision;
            $strWhere = ' WHERE (revision > :lastRevision AND revision <= :maxRevision) ';

            $startAfterGuid = empty($startAfterGuid) ? $startAfterGuid = '' : $startAfterGuid;
            if (!empty($startAfterGuid)) {
                $strWhere = ' WHERE ((revision = :lastRevision AND  uuid > (UNHEX(REPLACE(:case_uuid' . ',"-",""))))  OR revision > :lastRevision) AND revision <= :maxRevision ';
                $bind['case_uuid'] = $startAfterGuid;
            } else {
                $strWhere = ' WHERE (revision > :lastRevision AND revision <= :maxRevision) ';
            }

            $bind['lastRevision'] = $lastRevision;
            $bind['maxRevision'] = $maxRevision;

            if (!empty($excludeRevisions)) {
                $arrExcludeRevisions = explode(',', $excludeRevisions);
                $strWhere .= ' AND revision NOT IN (:exclude_revisions) ';
                $bind['exclude_revisions'] = $arrExcludeRevisions;
            }

            if (!empty($universe)) {
                $strWhere .= ' AND (`key` LIKE :universe) ';
                $universe .= '%';
                $bind['universe'] = $universe;
            }

            $stm = 'SELECT count(*)  FROM ' . $dictName . $strWhere;

            return (int) $this->pdo->fetchValue($stm, $bind);
        } catch (\Exception $e) {
            throw new \Exception('Failed in getCaseCount ' . $dictName, 0, $e);
        }
    }

}
