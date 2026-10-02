<?php


namespace App\Controller\api;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Request;
use App\CSPro\FileManager\CSProFileManager;
use Psr\Log\LoggerInterface;
use App\Service\PdoHelper;
use App\Service\OAuthHelper;
use App\CSPro\CSProResponse;
use App\CSPro\FileManager\CSProPathValidator;

class FoldersController extends AbstractController implements ApiTokenAuthenticatedController {

    public function __construct(private OAuthHelper $oauthService, private PdoHelper $pdo, private LoggerInterface $logger)
    {
    }

    #[Route('/folders/{folderPath}', methods: ['GET'], requirements: ['folderPath' => '.*'])]
    function getDirectoryListing(Request $request, $folderPath): CSProResponse {
        $getFileMd5 = $request->headers->get('x-csw-get-file-md5');
        $getFileMd5 = isset($getFileMd5) ? filter_var($getFileMd5, FILTER_VALIDATE_BOOLEAN) : true;

        // Nouveau : paramètre de filtre par nom de fichier (recherche "contient", insensible à la casse)
        $nameFilter = $request->query->get('nameContains');

        $fileManager = new CSProFileManager($this->logger);
        $fileManager->rootFolder = $this->getParameter('csweb_api_files_folder');
        $dirList = $fileManager->getDirectoryListing($folderPath, $getFileMd5);
        $response = null;
        $cleanPath = CSProPathValidator::validateAndSanitize($folderPath, $fileManager->rootFolder);

        if (is_dir($fileManager->rootFolder . DIRECTORY_SEPARATOR . $cleanPath)) {
            // Applique le filtre si le paramètre est présent
            if (!empty($nameFilter)) {
                $dirList = array_values(array_filter($dirList, function ($entry) use ($nameFilter) {
                    // On ne filtre que les fichiers ; les dossiers restent visibles
                    if (is_array($entry) && ($entry['type'] ?? null) === 'file') {
                        return stripos($entry['name'], $nameFilter) !== false;
                    }
                    if (is_object($entry) && ($entry->type ?? null) === 'file') {
                        return stripos($entry->name, $nameFilter) !== false;
                    }
                    return true; // garde les dossiers / autres types tels quels
                }));
            }
            $response = new CSProResponse(json_encode($dirList, JSON_THROW_ON_ERROR));
        } else {
            $response = new CSProResponse();
            $response->setError(404, 'directory_not_found', 'Directory not found');
        }
        $response->headers->set('Content-Length', strlen($response->getContent()));
        return $response;
    }
}
