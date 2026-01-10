// Variables para controlar el estado del análisis
let currentDomain = "";
let lastData = null; // Guardará el objeto JSON completo
let pollInterval = null;
let pollAttempts = null;
let dnsAttempts = 0;
const MAX_DNS_ATTEMPTS=20;

// Referencias a los elementos del DOM
const btnAnalyze = document.getElementById('btnAnalyze');
const domainInput = document.getElementById('domainInput');
const resultContainer = document.getElementById('resultContainer');
const endpointTable = document.getElementById('endpointTable');
const downloadSection = document.getElementById('downloadSection');

const statusMessages = {
    "DNS": { msg: "Resolving domain DNS...", color: "info", icon: "bi-search" },
    "IN_PROGRESS": { msg: "Scanning server configuration...", color: "primary", icon: "bi-gear-wide-connected" },
    "READY": { msg: "Analysis complete!", color: "success", icon: "bi-check-all" },
    "ERROR": { msg: "An error occurred during the scan.", color: "danger", icon: "bi-x-circle" }
};
const specialErrorHandlers = {
    "Rate limit exceeded": {
        title: "Slow down!",
        msg: "You've sent too many requests. SSL Labs needs a break (wait 5-10 min).",
        type: "warning"
    },
    "Internal error": {
        title: "API Error",
        msg: "SSL Labs servers are having trouble. Try again in a moment.",
        type: "danger"
    },
    "Unable to resolve domain name": {
        title: "DNS Error",
        msg: "We couldn't find this domain. Check for typos (e.g., example.com).",
        type: "danger"
    },
    "Service not available": {
        title: "Maintenance",
        msg: "The engine is currently overloaded or under maintenance.",
        type: "warning"
    }
};

// Configurar el evento de click para el botón principal
if (btnAnalyze) {
    btnAnalyze.addEventListener('click', startAnalysis);
}

// Configurar el evento para el botón de descarga
const btnDownload = document.getElementById('btnDownload');
if (btnDownload) {
    btnDownload.addEventListener('click', () => {
        if (currentDomain) {
            window.location.href = `/download?domain=${encodeURIComponent(currentDomain)}`;
        }
    });
}

/**
 * Inicia el proceso de análisis
 */
function startAnalysis() {
    const domain = domainInput.value.trim();
    if (!domain) {
        alert("Por favor, ingresa un dominio válido.");
        return;
    }

    // Configuración inicial de la UI
    currentDomain = domain;

    pollAttempts = 0; // Reiniciar contador de tiempo
    stopPolling();
    resultContainer.style.display = 'block';
    downloadSection.style.display = 'none';
    endpointTable.innerHTML = '<tr><td colspan="2" class="text-center text-muted">Iniciando consulta...</td></tr>';
    
    const errorDisplay = document.getElementById('error-message-display');
    const bannerStatusDisplay = document.getElementById('status-banner');
    if (errorDisplay) {
        errorDisplay.innerHTML = '';      // Borra el contenido
        errorDisplay.classList.add('d-none'); // Lo oculta
    }
    if (bannerStatusDisplay) {
        bannerStatusDisplay.innerHTML = '';      // Borra el contenido
        bannerStatusDisplay.classList.add('d-none'); // Lo oculta
    }
    // Limpiar cualquier intervalo previo antes de empezar uno nuevo
    if (pollInterval) clearInterval(pollInterval);
    
    // Ejecutar la primera consulta inmediatamente
    pollServer();
}

/**
 * Consulta al servidor Go por el estado del análisis
 */
async function pollServer() {
    try {
        const response = await fetch(`/check?domain=${encodeURIComponent(currentDomain)}`);
        
        if (!response.ok) {
            throw new Error(`Error en servidor: ${response.status}`);
        }

        const text = await response.text();
        if (!text || text.trim() === "") return; 

        const data = JSON.parse(text);

        // --- 1. NUEVA LÓGICA: MANEJO DE ERRORES ESPECIALES ---
        if (data.status === "ERROR" || (data.statusMessage && data.statusMessage.includes("Rate limit"))) {
            stopPolling();
            // Buscamos si es un error conocido en nuestro diccionario
            const errorInfo = specialErrorHandlers[data.statusMessage] || {
                title: "Analysis Failed",
                msg: data.statusMessage || "An unexpected error occurred.",
                type: "danger"
            };
            
            // Mostramos el mensaje visual y detenemos todo
            showErrorMessage(errorInfo);
            stopPolling();
            document.getElementById('resStatus').innerText = "FAILED";
            return; // Salimos de la función para no intentar renderizar basura
        }
        // -------------------------------------------------------

            //SI EL DNS no resuelve
        if (data.status === "DNS") {
            dnsAttempts++; 
            console.log(`DNS Attempt: ${dnsAttempts}/${MAX_DNS_ATTEMPTS}`);
            
            if (dnsAttempts >= MAX_DNS_ATTEMPTS) {
                
                showErrorMessage({
                    title: "DNS Timeout",
                    msg: "The domain is taking too long to resolve. Please verify if it exists.",
                    type: "warning"
                });
                  document.getElementById('status-banner').innerText = "";
                stopPolling();
                return; // Detenemos la ejecución
            }
        } else {
            // Si el estado ya no es DNS (ej: IN_PROGRESS), reseteamos para futuros escaneos
            dnsAttempts = 0; 
        }

        //actualizar estado de la consulta
        updateStatusBanner(data);

        // ACTUALIZACIÓN DE INTERFAZ
        document.getElementById('resHost').innerText = `Results for: ${data.host || currentDomain}`;
        document.getElementById('resStatus').innerText = data.status || "Processing...";

        // Formateo de fecha y duración
        const rawTime = data.testTime > 0 ? data.testTime : Date.now();
        const testTimeFormatted = new Date(rawTime).toLocaleString('en-US', {
            day: '2-digit', month: '2-digit', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });

        const TestDuration = calculateDuration(data.startTime, data.testTime);
        document.getElementById('resTestDate').innerText = "Testing Date: " + testTimeFormatted;
        document.getElementById('resTestDuration').innerText = "Test Duration: " + TestDuration;

        renderEndpoints(data);
            
        // LÓGICA DE REINTENTO (POLLING)
        if (data.status === "READY") {
            lastData = data;
            //downloadSection.style.display = 'block';
            if (downloadSection) {
            downloadSection.style.display = 'block'; // Mostramos el botón
             }
            stopPolling();
        } else {
            if (!pollInterval) {
                pollInterval = setInterval(pollServer, 3000);
            }
        }

    } catch (error) {
        console.error("Error detallado en pollServer:", error);
        // Mostrar alerta de error de red
        showErrorMessage({
            title: "Connection Error",
            msg: "Unable to reach the server. Please try again.",
            type: "danger"
        });
       stopPolling();
    }
}

function stopPolling() {
    if (pollInterval) {
        clearInterval(pollInterval); // Detiene el reloj
        pollInterval = null;         // Limpia la variable
        console.log("🛑 Polling detenido.");
    }
}
/**
 * Genera las filas de la tabla de resultados
 */
function renderEndpoints(data) {
    const tableBody = document.getElementById('endpointTable');
    if (!tableBody) return;

    if (!data || !data.endpoints) return;

    const certsMap = {};
    if (data.certs) {
        data.certs.forEach(c => { certsMap[c.id] = c; });
    }

    const getColor = (g) => {
        if (!g) return 'bg-secondary';
        return g.startsWith('A') ? 'bg-success' : (g.startsWith('B') ? 'bg-warning' : 'bg-danger');
    };

    try {
        const rows = data.endpoints.map((ep, index) => {
            const details = ep.details || {};
            const certChains = details.certChains || [];
            const certIds = certChains.length > 0 ? (certChains[0].certIds || []) : [];
            const fullCerts = certIds.map(id => certsMap[id]).filter(c => c);

            console.log("fullcerts", fullCerts)
                // Lógica para Forward Secrecy (es un bitmask, generalmente > 0 es bueno)
      // 1. Forward Secrecy (Es una característica positiva, debe estar activada)
const fsStatus = details.forwardSecrecy > 0 
    ? '<span style="color: #198754;">✅ FS</span>'  // Chulo verde si tiene
    : '<span style="color: #dc3545;">❌ FS</span>'; // X roja si no tiene

// 2. Heartbleed - Es malo tenerlo (Vulnerabilidad)
const hbStatus = !details.heartbleed 
    ? '<span style="color: #198754;">✅ Heartbleed</span>' // Chulo si NO es vulnerable
    : '<span style="color: #dc3545;">❌ Heartbleed</span>'; // X si ES vulnerable

// 3. BEAST - Es malo tenerlo (Vulnerabilidad)
const beastStatus = !details.vulnBeast 
    ? '<span style="color: #198754;">✅ BEAST</span>'      // Chulo si NO es vulnerable
    : '<span style="color: #dc3545;">❌ BEAST</span>';

            
            const rowId = `certs-${index}`;

            return `
            
                <tr class="align-middle border-primary border-top  mb-5">
                    
               <td>
                    <div class="d-flex gap-1 flex-wrap fs-6"><strong>IP: ${ep.ipAddress}</strong> 
                    <span class="small">ServerName: ${ep.serverName}</span></div>
                    </td>
                    <td><div  class="d-flex gap-1 flex-wrap">
                     <span class="small"> Time Duration: ${ep.duration} ms</span>
                    <span  class="small">Progress: ${ep.progress} %</span></div></td>
                    
                    <td class="w-auto text-nowrap text-center"><span class="badge fs-5   ${getColor(ep.grade)}">${ep.grade || '?'}</span></td>
                    <td>
                    <div class="d-flex gap-1 flex-wrap">${(details.protocols || []).map(p => `<span class="badge ${getProtocolClass(p.version)} bg-info me-1">${p.version + " "+p.name}</span>`).join("") || '---'}  </div></td>
                   <td>
                <div class="d-flex gap-1 flex-wrap">
                ${hbStatus}
                ${beastStatus}
                ${fsStatus}
                </div>
        </td>
         <td><strong> ${fullCerts.length}</strong> </td>
                    
                </tr>
                <tr>${renderCertChainTable(fullCerts)}</tr>
                
                <tr class="border-0"><td colspan="100%" class="py-3 border-0"></td></tr>`  ;
              
        }).join("");

        tableBody.innerHTML = rows;
        
        
    } catch (e) {
        console.error("Error dentro del mapeo:", e);
    }
}
/**
 * Retorna la clase de Bootstrap según la nota (grade)
 */
function getGradeClass(grade) {
    if (!grade) return "bg-secondary";
    const g = grade.toUpperCase();
    if (g.startsWith('A')) return "bg-success";
    if (g.startsWith('B')) return "bg-primary";
    if (g.startsWith('C')) return "bg-warning text-dark";
    if (g.startsWith('D') || g.startsWith('F')) return "bg-danger";
    return "bg-info text-dark";
}
function renderCertChainTable(certs) {
    if (!certs || certs.length === 0) return "No hay datos";

    const rows = certs.map((cert, index) => {
        const start = new Date(cert.notBefore).toLocaleDateString();
        const end = new Date(cert.notAfter).toLocaleDateString();
        
        const isLeaf = index === 0;

        return `
       
            <tr>
                <td>${isLeaf ? '<b>📜 Final</b>' : '🔗 Interm.'}</td>
                <td class="small">${cert.subject}</td>
                <td><span class="badge bg-light text-dark border">${cert.keyAlg} ${cert.keySize} / ${cert.sigAlg}</span></td>
              
                <td > ${getRevocationStatus(cert.revocationStatus)}</td>
                <td class="small">${start} - ${end}</td>
                
                
            </tr>`;
    }).join("");

    return `
     <th class="font-size: 0.8rem">Certificates</th>
        <table class="table table-sm table-hover mt-2 shadow-sm">
            <thead class="table-secondary" style="font-size: 0.6rem;">
                <tr>
                    <th>Grade</th><th>Subject</th><th>Criptography</th><th>Revocation Status</th><th> Validation Term</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>`;
}
function getRevocationBadge(status) {
    switch(status) {
        case 2: return '<span class="badge bg-success">Válido</span>';
        case 3: return '<span class="badge bg-danger">Revocado</span>';
        default: return '<span class="badge bg-secondary">No verif.</span>';
    }
}
const getProtocolClass = (version) => {
    if (!version) return 'bg-secondary';
    
    // TLS 1.3 y 1.2 son los estándares actuales seguros
    if (version.includes('1.3')) return 'bg-success'; // Verde
    if (version.includes('1.2')) return 'bg-primary'; // Azul
    
    // TLS 1.1 y 1.0 son antiguos
    if (version.includes('1.1') || version.includes('1.0')) return 'bg-warning text-dark'; // Amarillo
    
    // SSL es crítico/inseguro
    if (version.toUpperCase().includes('SSL')) return 'bg-danger'; // Rojo
    
    return 'bg-secondary'; // Otros
};

function calculateDuration(start, end) {
    if (!end || end <= start) return "En progreso...";
    
    const diffInSeconds = Math.round((end - start) / 1000);
    // Si el análisis se entregó en menos de 5 segundos pero dice que duró 20 min
    // es una señal clara de caché.
    if (diffInSeconds > 500) { 
        return "Instantáneo (desde caché)";
    }
    
    //return `${minutes}m ${seconds}s`;
    return `${diffInSeconds} seconds`;
}

function returnFormattedDate(rawTime){
    const testTimeFormatted = new Date(rawTime).toLocaleString('es-ES', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit' // Opcional: añade segundos para ver el cambio en el polling
});
return testTimeFormatted;
}

function getRevocationStatus(status) {
    const statuses = {
        0: { text: "Not checked", class: "bg-secondary" },
        1: { text: "REVOKED", class: "bg-danger" },
        2: { text: "SAFE AND WORKING", class: "bg-success" },
        3: { text: "Check Unavailable", class: "bg-warning text-dark" },
        4: { text: "No revocation info", class: "bg-light text-dark border" },
        5: { text: "Internal error", class: "bg-danger" }
    };

    const s = statuses[status] || { text: "Unknown", class: "bg-secondary" };
    return `<span class="badge ${s.class}">${s.text}</span>`;
}

function updateStatusBanner(data) {
    const banner = document.getElementById('status-banner');
    if (!banner) return;

    // Obtenemos la configuración según el status, o uno por defecto
    const config = statusMessages[data.status] || { msg: data.status, color: "secondary", icon: "bi-info-circle" };
    
    // Si la API trae un mensaje específico (como "Rate limit exceeded"), lo usamos
    const detailMsg = data.statusMessage ? `: ${data.statusMessage}` : '';

    banner.className = `alert alert-${config.color} d-flex align-items-center shadow-sm`;
    banner.innerHTML = `
        <i class="bi ${config.icon} me-2 fs-4"></i>
        <div>
            <strong>${config.msg}</strong> ${detailMsg}
            ${data.status !== 'READY' ? '<div class="spinner-border spinner-border-sm ms-2" role="status"></div>' : ''}
        </div>
    `;
}

/**
 * Muestra un mensaje de error visual al usuario
 * @param {Object} info - Objeto con title, msg y type
 */
function showErrorMessage(info) {
    // 1. Log en consola para depuración
    console.error(`[${info.title}]: ${info.msg}`);

    // 2. Intentar mostrarlo en un elemento de alerta si tienes uno en el HTML
    const errorDisplay = document.getElementById('error-message-display');
    
    if (errorDisplay) {
        errorDisplay.innerHTML = `
            <div class="alert alert-${info.type || 'danger'} alert-dismissible fade show" role="alert">
                <strong>${info.title}:</strong> ${info.msg}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
        errorDisplay.classList.remove('d-none');
    } else {
        // Fallback: Si no tienes el elemento en el HTML, usa un alert normal
        alert(`${info.title}\n\n${info.msg}`);
    }
}