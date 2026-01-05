// frontend/src/components/ui/ConfirmModal.jsx
import React from "react";
import Modal from "./Modal";
import Button from "./Button";

export function ConfirmModal({ open, onClose, onConfirm, message }) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Confirm Action"
      actions={[
        <Button key="cancel" variant="outline" onClick={onClose}>
          Cancel
        </Button>,
        <Button key="ok" variant="danger" onClick={onConfirm}>
          Confirm
        </Button>,
      ]}
    >
      <p className="text-white/90">{message}</p>
    </Modal>
  );
}

export default ConfirmModal;
