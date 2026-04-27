import { Button, Modal } from "react-bootstrap";
import { prettyCode } from "../utils/utils";

export default function JSONModal({
  show,
  onHide,
  modalTitle,
  modalData,
  size,
}) {
  return (
    <Modal show={show} onHide={onHide} size={size}>
      <Modal.Header closeButton>
        <Modal.Title className="text-truncate">{modalTitle}</Modal.Title>
      </Modal.Header>
      <Modal.Body>{prettyCode("json", modalData)}</Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
