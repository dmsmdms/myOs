'use strict'

function fillListTbody(tbody, list) {
	while (tbody.firstElementChild != undefined) {
		tbody.firstElementChild.remove();
	}

	for (let i = 0; i < list.length; i++) {
		const tr = document.createElement('tr');
		const nameTd = document.createElement('td');
		const pidTd = document.createElement('td');
		const virtMemTd = document.createElement('td');
		const phyMemTd = document.createElement('td');
		const shMemTd = document.createElement('td');
		const statusTd = document.createElement('td');
		const cpuTd = document.createElement('td');
		const memTd = document.createElement('td');
		const timeTd = document.createElement('td');
		const runTd = document.createElement('td');
		const stopTd = document.createElement('td');
		const runBtn = document.createElement('button');
		const stopBtn = document.createElement('button');
		const item = list[i];
		
		tbody.appendChild(tr);
		tr.appendChild(nameTd);
		tr.appendChild(pidTd);
		tr.appendChild(virtMemTd);
		tr.appendChild(phyMemTd);
		tr.appendChild(shMemTd);
		tr.appendChild(statusTd);
		tr.appendChild(cpuTd);
		tr.appendChild(memTd);
		tr.appendChild(timeTd);
		tr.appendChild(runTd);
		tr.appendChild(stopTd);
		runTd.appendChild(runBtn);
		stopTd.appendChild(stopBtn);
		
		nameTd.innerText = item.name;
		pidTd.innerText = item.pid;
		virtMemTd.innerText = item.virtMem;
		phyMemTd.innerText = item.phyMem;
		shMemTd.innerText = item.shMem;
		statusTd.innerText = item.status;
		cpuTd.innerText = item.cpu;
		memTd.innerText = item.mem;
		timeTd.innerText = item.time;
	}
}

function getStatusStr(statusCode) {
	const statusStr = [
		'Sleep',
	];
	
	return statusStr[statusCode];
}

function decodeInfo(blob) {
	const decoder = new TextDecoder('utf-8');
	const data = new DataView(blob);
	const list = [];
	let offsset = 0;
	
	const length = data.getUint8(offset);
	offset += 1;
	
	for (let i = 0; i < length; i++) {
		const nameLen = data.getUint8(offset);
		offset += 1;
		
		const nameArr = new Uint8Array(data, offset, nameLen);
		const name = decoder.decode(nameArr);
		offset += nameLen;
		
		const pid = data.getUint16(offset);
		offset += 2;
		
		const virtMem = data.getUint32(offset);
		offset += 4;
		
		const phyMem = data.getUint32(offset);
		offset += 4;
		
		const shMem = data.getUint32(offset);
		offset += 4;
		
		const statusCode = data.getUint8(offset);
		const status = getStatusStr(statusCode);
		offset += 1;
		
		const cpu = data.getUint16(offset);
		offset += 2;
		
		const mem = data.getUint16(offset);
		offset += 2;
		
		const time = data.getUint32(offset);
		offset += 4;
		
		const item = {
			name: name,
			pid: pid,
			virtMem: virtMem,
			phyMem: phyMem,
			shMem: shMem,
			status: status,
			cpu: cpu,
			mem: mem,
			time: time,
		};
		
		list.push(item);
	}
	
	const info = {
		list: list,
	};

	return info;
}

function getInfo(tbody) {
	const xhr = new XMLHttpRequest();

	xhr.open('GET', 'info');
	xhr.send();

	xhr.onload = function() {
		if (xhr.readyState != 4) {
			return;
		}

		if (xhr.status == 200) {
			const info = decodeInfo(xhr.response);
			fillListTbody(tbody, info.list);
		} else {
			console.err(`HTTP code ${ xhr.status }`);
		}
	};
	
	xhr.onerror = function () {
		console.err('HTTP error');
	};
}

onload = function () {
	const listTbody = document.getElementById('list-tbody');
	
	setInterval(function () {
		getInfo(tbody);	
	}, 500);	
};
